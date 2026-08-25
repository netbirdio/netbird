package quic

import (
	"context"
	"fmt"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	log "github.com/sirupsen/logrus"
)

// logSink implements both qlogwriter.Trace and qlogwriter.Recorder, forwarding
// the few qlog events the relay client cares about to logrus instead of
// writing a qlog file. It holds no mutable state and logrus entries are safe
// to share, so one value can serve every producer on the connection.
type logSink struct {
	log *log.Entry
}

func (s logSink) AddProducer() qlogwriter.Recorder { return s }

func (s logSink) SupportsSchemas(schema string) bool { return schema == qlog.EventSchema }

func (s logSink) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case qlog.MTUUpdated:
		if e.Done {
			s.log.Infof("QUIC path MTU settled at %d", e.Value)
			return
		}
		s.log.Debugf("QUIC path MTU probing at %d", e.Value)
	case qlog.ConnectionClosed:
		s.log.Debugf("QUIC connection closed: %s", closeReason(e))
	}
}

func (s logSink) Close() error { return nil }

// connectionTracer returns a QUIC tracer that logs the DPLPMTUD result and the
// reason a relay connection closed, so the path MTU settled on and teardown
// cause are visible in logs. Lines carry the relay address as a structured
// field, matching the rest of the relay client logging.
func connectionTracer(addr string) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	relayLog := log.WithField("relay", addr)
	return func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return logSink{log: relayLog}
	}
}

// closeReason renders a ConnectionClosed event as a single line. The event
// carries the error as separate initiator, code, trigger and reason fields,
// any of which may be unset.
func closeReason(e qlog.ConnectionClosed) string {
	parts := []string{fmt.Sprintf("closed by %s", e.Initiator)}
	switch {
	case e.ConnectionError != nil:
		parts = append(parts, fmt.Sprintf("transport error: %s", *e.ConnectionError))
	case e.ApplicationError != nil:
		parts = append(parts, fmt.Sprintf("application error: %d", *e.ApplicationError))
	}
	if e.Trigger != "" {
		parts = append(parts, fmt.Sprintf("trigger: %s", e.Trigger))
	}
	if e.Reason != "" {
		parts = append(parts, fmt.Sprintf("reason: %s", e.Reason))
	}
	return strings.Join(parts, ", ")
}
