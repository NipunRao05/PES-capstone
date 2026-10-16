// Package operational owns process-local aggregate proxy telemetry.
package operational

import "sync/atomic"

// DeceptionFallbacks counts failed decision calls returning to the existing proxy path.
var DeceptionFallbacks atomic.Int64
