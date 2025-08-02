package monotime

import (
	"time"
)

var (
	baseWallTime time.Time
	baseWallNano int64
)

type Time int64

func init() {
	baseWallTime = time.Now()
	baseWallNano = baseWallTime.UnixNano()
}

// Now returns the current time as Unix nanoseconds (int64).
// It uses monotonic time measurement from the base time to ensure
// the returned value increases monotonically and is not affected
// by system clock adjustments.
//
// Performance optimization: By capturing the base wall time once at startup
// and using time.Since() for elapsed calculation, this avoids repeated
// time.Now() calls and leverages Go's internal monotonic clock for
// efficient duration measurement.
func Now() Time {
	elapsed := time.Since(baseWallTime)
	return Time(baseWallNano + int64(elapsed))
}

func Since(t Time) time.Duration {
	return time.Duration(Now() - t)
}
