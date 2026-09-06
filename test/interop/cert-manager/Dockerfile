# Wraps the statically linked test server. The binary is built outside the image so the Go build
# cache is reused and the image holds nothing but the executable.
FROM scratch
COPY acme-server /acme-server
USER 65532:65532
ENTRYPOINT ["/acme-server"]
