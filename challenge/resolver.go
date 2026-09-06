package challenge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	acmeserver "github.com/misiektoja/go-acme-server"
)

// Configures explicit recursive DNS endpoints with bounded messages and alias traversal.
type ResolverOptions struct {
	// Numeric TCP resolver endpoints, including ports, with at most three entries.
	Servers          []netip.AddrPort
	Timeout          time.Duration
	MaxCNAMEs        int
	MaxResponseBytes int
	MaxRecords       int
}

// Queries only configured resolvers over TCP and validates response ownership before using records.
type Resolver struct {
	servers    []netip.AddrPort
	timeout    time.Duration
	maxCNAMEs  int
	maxBytes   int
	maxRecords int
}

// Constructs a resolver with ten-second, eight-alias, 16-KiB and 64-record defaults.
func NewResolver(options ResolverOptions) (*Resolver, error) {
	if len(options.Servers) == 0 || len(options.Servers) > 3 || options.Timeout < 0 || options.MaxCNAMEs < 0 ||
		options.MaxResponseBytes < 0 || options.MaxResponseBytes > 65535 || options.MaxRecords < 0 {
		return nil, errors.New("challenge: invalid resolver configuration")
	}
	for _, server := range options.Servers {
		if !server.IsValid() || server.Port() == 0 || server.Addr().Zone() != "" {
			return nil, errors.New("challenge: invalid resolver endpoint")
		}
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.MaxCNAMEs == 0 {
		options.MaxCNAMEs = 8
	}
	if options.MaxResponseBytes == 0 {
		options.MaxResponseBytes = 16 << 10
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = 64
	}
	return &Resolver{servers: slices.Clone(options.Servers), timeout: options.Timeout, maxCNAMEs: options.MaxCNAMEs,
		maxBytes: options.MaxResponseBytes, maxRecords: options.MaxRecords}, nil
}

// Returns each TXT record separately while joining the character strings within that record.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	records, err := r.lookup(ctx, name, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(records))
	for _, record := range records {
		if value, ok := record.Body.(*dnsmessage.TXTResource); ok {
			values = append(values, strings.Join(value.TXT, ""))
		}
	}
	return values, nil
}

// Resolves A and AAAA records through the same bounded resolver policy used for TXT proofs.
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, errors.New("challenge: unsupported address family")
	}
	var addresses []netip.Addr
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if network == "ip4" && typ == dnsmessage.TypeAAAA || network == "ip6" && typ == dnsmessage.TypeA {
			continue
		}
		records, err := r.lookup(ctx, host, typ)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			switch value := record.Body.(type) {
			case *dnsmessage.AResource:
				addresses = append(addresses, netip.AddrFrom4(value.A))
			case *dnsmessage.AAAAResource:
				addresses = append(addresses, netip.AddrFrom16(value.AAAA))
			}
		}
	}
	return addresses, nil
}

// Traverses only answer-owner CNAMEs and never accepts unrelated records as proof.
func (r *Resolver) lookup(ctx context.Context, name string, typ dnsmessage.Type) ([]dnsmessage.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	name = strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	seen := map[string]bool{name: true}
	var answers []dnsmessage.Resource
	for hops := 0; hops <= r.maxCNAMEs; hops++ {
		if answers == nil {
			var err error
			answers, err = r.query(ctx, name, typ)
			if err != nil {
				return nil, err
			}
		}
		matching, alias, err := matchingAnswers(answers, name, typ)
		if err != nil {
			return nil, err
		}
		if alias == "" {
			return matching, nil
		}
		if hops == r.maxCNAMEs || seen[alias] {
			return nil, dnsFailure("CNAME traversal limit or loop")
		}
		seen[alias] = true
		name = alias
		present := slices.ContainsFunc(answers, func(a dnsmessage.Resource) bool {
			return strings.EqualFold(a.Header.Name.String(), name)
		})
		if !present {
			answers = nil
		}
	}
	return nil, dnsFailure("CNAME traversal limit")
}

// Selects records for one owner and rejects contradictory aliases at that owner.
func matchingAnswers(answers []dnsmessage.Resource, name string, typ dnsmessage.Type) ([]dnsmessage.Resource, string, error) {
	var matching []dnsmessage.Resource
	alias := ""
	for _, answer := range answers {
		if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), name) {
			continue
		}
		if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			target := strings.ToLower(cname.CNAME.String())
			if alias != "" && alias != target {
				return nil, "", dnsFailure("conflicting CNAME records")
			}
			alias = target
		} else if answer.Header.Type == typ {
			matching = append(matching, answer)
		}
	}
	if alias != "" && len(matching) > 0 {
		return nil, "", dnsFailure("CNAME and proof records share an owner")
	}
	return matching, alias, nil
}

// Tries each explicitly configured resolver once for a bounded DNS question.
func (r *Resolver) query(ctx context.Context, name string, typ dnsmessage.Type) ([]dnsmessage.Resource, error) {
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, dnsFailure("invalid DNS query name")
	}
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, err
	}
	question := dnsmessage.Question{Name: qname, Type: typ, Class: dnsmessage.ClassINET}
	message := dnsmessage.Message{
		ID: binary.BigEndian.Uint16(randomID[:]), RecursionDesired: true,
		Questions: []dnsmessage.Question{question}}
	query, err := message.Pack()
	if err != nil {
		return nil, err
	}
	var last error
	for _, server := range r.servers {
		response, err := r.exchange(ctx, server, query)
		if err != nil {
			last = err
			continue
		}
		answers, err := r.parseResponse(response, message.ID, question)
		if err == nil {
			return answers, nil
		}
		if _, terminal := acmeserver.AsProblem(err); terminal {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("challenge: DNS query failed: %w", last)
}

// Exchanges one length-prefixed DNS message with a numeric TCP resolver endpoint.
func (r *Resolver) exchange(ctx context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	wire := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(wire[:2], uint16(len(query))) //nolint:gosec // A DNS question is shorter than 65536 bytes.
	copy(wire[2:], query)
	if _, err := io.Copy(connection, strings.NewReader(string(wire))); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(connection, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	if length < 12 || length > r.maxBytes {
		return nil, dnsFailure("DNS response exceeds the message limit")
	}
	response := make([]byte, length)
	_, err = io.ReadFull(connection, response)
	return response, err
}

// Validates the DNS envelope before decoding bounded answer records.
func (r *Resolver) parseResponse(wire []byte, id uint16, question dnsmessage.Question) ([]dnsmessage.Resource, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(wire)
	if err != nil || header.ID != id || !header.Response || header.OpCode != 0 || header.Truncated {
		return nil, dnsFailure("invalid DNS response header")
	}
	count := int(binary.BigEndian.Uint16(wire[6:8])) + int(binary.BigEndian.Uint16(wire[8:10])) +
		int(binary.BigEndian.Uint16(wire[10:12]))
	if count > r.maxRecords {
		return nil, dnsFailure("DNS response exceeds the record limit")
	}
	if binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return nil, dnsFailure("DNS response question count differs")
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Type != question.Type || questions[0].Class != question.Class ||
		!strings.EqualFold(questions[0].Name.String(), question.Name.String()) {
		return nil, dnsFailure("DNS response question differs")
	}
	if header.RCode == dnsmessage.RCodeNameError {
		return nil, dnsFailure("DNS name does not exist")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, errors.New("DNS resolver returned a transient failure")
	}
	answers, err := validationAnswers(&parser)
	if err != nil {
		return nil, dnsFailure("invalid DNS answer encoding")
	}
	return answers, nil
}

// Decodes only record types used by validation and skips every other bounded record body.
func validationAnswers(parser *dnsmessage.Parser) ([]dnsmessage.Resource, error) {
	var answers []dnsmessage.Resource
	for {
		header, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return answers, nil
		}
		if err != nil {
			return nil, err
		}
		body, err := validationBody(parser, header.Type)
		if err != nil {
			return nil, err
		}
		if body != nil {
			answers = append(answers, dnsmessage.Resource{Header: header, Body: body})
		}
	}
}

// Selects a narrow DNS decoder without invoking parsers for unrelated protocols.
func validationBody(parser *dnsmessage.Parser, typ dnsmessage.Type) (dnsmessage.ResourceBody, error) {
	switch typ { //nolint:exhaustive // Other DNS types are skipped without decoding.
	case dnsmessage.TypeA:
		value, err := parser.AResource()
		return &value, err
	case dnsmessage.TypeAAAA:
		value, err := parser.AAAAResource()
		return &value, err
	case dnsmessage.TypeCNAME:
		value, err := parser.CNAMEResource()
		return &value, err
	case dnsmessage.TypeTXT:
		value, err := parser.TXTResource()
		return &value, err
	default:
		return nil, parser.SkipAnswer()
	}
}

// Returns a terminal DNS proof failure with no record content.
func dnsFailure(detail string) *acmeserver.Problem {
	return acmeserver.NewProblem(acmeserver.ErrorDNS, detail)
}
