// Package clock provides the server's wall clock.
package clock

import "time"

// Now returns the current wall-clock time.
func Now() time.Time { return time.Now() }
