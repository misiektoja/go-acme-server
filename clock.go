package acmeserver

import "time"

// Supplies the current time.
type Clock interface {
	Now() time.Time
}

// Adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Returns the time reported by the function.
func (f ClockFunc) Now() time.Time { return f() }

// Returns a Clock backed by the wall clock.
func SystemClock() Clock { return ClockFunc(time.Now) }
