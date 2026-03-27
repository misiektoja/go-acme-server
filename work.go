package acmeserver

import "time"

// Names what a background task does.
type TaskKind string

// Task kinds.
const (
	// Validates the challenge named by Task.TargetID.
	TaskValidate TaskKind = "validate"
	// Issues the certificate for the order named by Task.TargetID.
	TaskIssue TaskKind = "issue"
)

// A unit of persisted background work. Run claims tasks with a lease and a fence so a worker
// that lost its lease cannot commit a stale result.
type Task struct {
	ID        string
	Kind      TaskKind
	TargetID  string
	AccountID string
	// The earliest time a worker may claim the task.
	RunAt time.Time
	// The number of claims so far.
	Attempts int
	// The end of the current lease. Zero when no worker holds the task.
	LeaseUntil time.Time
	// Increases on every claim. Completion calls must present the current value.
	Fence     uint64
	CreatedAt time.Time
}
