package alignedhb

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// MetadataKey is the gRPC metadata key that carries the aligned heartbeat
// request when a Signal stream opens, and the answer in the header the Signal
// server sends back on that stream.
const MetadataKey = "x-netbird-aligned-heartbeat"

const (
	periodPrefix   = "period="
	fieldSeparator = ";"
)

var errInvalidValue = errors.New("invalid aligned heartbeat metadata value")

// MetadataValue encodes period as "period=<s>", the value of both the request
// and the answer.
func MetadataValue(period time.Duration) string {
	return periodPrefix + strconv.FormatInt(int64(period/time.Second), 10)
}

// ParseMetadataValue parses a value that starts with "period=<s>", followed
// by the end or by ";". Anything after the ";" is ignored, so a later release
// can add fields there. Any other value is an error, and the stream then stays
// stock. The period is returned raw; the server clamps a request and the
// client clamps an answer with ClampPeriod.
func ParseMetadataValue(v string) (time.Duration, error) {
	raw, ok := strings.CutPrefix(v, periodPrefix)
	if !ok {
		return 0, errInvalidValue
	}
	raw, _, _ = strings.Cut(raw, fieldSeparator)
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 {
		return 0, errInvalidValue
	}
	return time.Duration(n) * time.Second, nil
}
