// Package alignedhb holds the parts of the aligned heartbeat that clients and
// the Management, Signal and relay servers share: the capability values sent
// when a stream opens, the server answers, and the heartbeat schedule.
//
// A client asks for the aligned heartbeat on each stream it opens. A server
// that supports it answers on the same stream, and only then do both sides
// change behaviour. Without an answer both sides stay stock.
package alignedhb

import (
	"runtime"
	"time"
)

const (
	// DefaultPeriod is the heartbeat period clients ask for.
	DefaultPeriod = 60 * time.Second
	// MinPeriod and MaxPeriod bound the period servers and clients accept.
	MinPeriod = 30 * time.Second
	MaxPeriod = 300 * time.Second
)

// Supported reports whether this build asks for the aligned heartbeat. Only
// mobile clients do: they are the ones that sleep between heartbeats.
func Supported() bool {
	return supportedOn(runtime.GOOS)
}

func supportedOn(goos string) bool {
	return goos == "ios" || goos == "android"
}

// ClientPeriod returns the period this client asks for. ok is false when the
// build does not ask for the aligned heartbeat.
func ClientPeriod() (period time.Duration, ok bool) {
	if !Supported() {
		return 0, false
	}
	return DefaultPeriod, true
}

// PeriodSeconds returns period in whole seconds for the wire, saturated to the
// uint32 range.
func PeriodSeconds(period time.Duration) uint32 {
	s := int64(period / time.Second)
	switch {
	case s <= 0:
		return 0
	case s > int64(^uint32(0)):
		return ^uint32(0)
	default:
		return uint32(s)
	}
}
