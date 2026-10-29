package quic

import (
	"testing"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

func TestCloseReason(t *testing.T) {
	transportErr := qlog.TransportErrorCode(0x2) // CONNECTION_REFUSED
	appErr := qlog.ApplicationErrorCode(42)

	tests := []struct {
		name  string
		event qlog.ConnectionClosed
		want  string
	}{
		{
			// A close carrying nothing but an initiator still reads sensibly.
			name:  "initiator only",
			event: qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal},
			want:  "closed by local",
		},
		{
			name: "transport error with trigger",
			event: qlog.ConnectionClosed{
				Initiator:       qlog.InitiatorRemote,
				ConnectionError: &transportErr,
				Trigger:         qlog.ConnectionCloseTriggerIdleTimeout,
			},
			want: "closed by remote, transport error: CONNECTION_REFUSED, trigger: idle_timeout",
		},
		{
			name: "application error with reason",
			event: qlog.ConnectionClosed{
				Initiator:        qlog.InitiatorLocal,
				ApplicationError: &appErr,
				Reason:           "bye",
			},
			want: "closed by local, application error: 42, reason: bye",
		},
		{
			// Transport and application errors are mutually exclusive in
			// practice; if both are set the transport code wins.
			name: "transport error takes precedence over application error",
			event: qlog.ConnectionClosed{
				Initiator:        qlog.InitiatorLocal,
				ConnectionError:  &transportErr,
				ApplicationError: &appErr,
			},
			want: "closed by local, transport error: CONNECTION_REFUSED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := closeReason(tt.event); got != tt.want {
				t.Errorf("closeReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogSinkRecordEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     qlogwriter.Event
		wantLevel log.Level
		wantMsg   string
	}{
		{
			name:      "settled MTU is logged at info",
			event:     qlog.MTUUpdated{Value: 1400, Done: true},
			wantLevel: log.InfoLevel,
			wantMsg:   "QUIC path MTU settled at 1400",
		},
		{
			// Probing fires repeatedly during discovery, so it stays at debug.
			name:      "MTU probe is logged at debug",
			event:     qlog.MTUUpdated{Value: 1300, Done: false},
			wantLevel: log.DebugLevel,
			wantMsg:   "QUIC path MTU probing at 1300",
		},
		{
			name:      "connection closed is logged at debug",
			event:     qlog.ConnectionClosed{Initiator: qlog.InitiatorRemote},
			wantLevel: log.DebugLevel,
			wantMsg:   "QUIC connection closed: closed by remote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, hook := test.NewNullLogger()
			logger.SetLevel(log.DebugLevel)
			recorder := logSink{log: logger.WithField("relay", "relay.example.com:443")}

			recorder.RecordEvent(tt.event)

			entries := hook.AllEntries()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want 1", len(entries))
			}
			if entries[0].Level != tt.wantLevel {
				t.Errorf("level = %v, want %v", entries[0].Level, tt.wantLevel)
			}
			if entries[0].Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", entries[0].Message, tt.wantMsg)
			}
			if relay := entries[0].Data["relay"]; relay != "relay.example.com:443" {
				t.Errorf("relay field = %v, want relay.example.com:443", relay)
			}
		})
	}
}

// Events the relay client does not care about must not produce log lines.
func TestLogSinkIgnoresUnhandledEvents(t *testing.T) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(log.DebugLevel)
	recorder := logSink{log: logger.WithField("relay", "relay.example.com:443")}

	recorder.RecordEvent(qlog.PacketLost{})

	if entries := hook.AllEntries(); len(entries) != 0 {
		t.Errorf("got %d log entries, want 0", len(entries))
	}
}

func TestLogSinkSupportsSchemas(t *testing.T) {
	trace := logSink{log: log.WithField("relay", "relay.example.com:443")}

	if !trace.SupportsSchemas(qlog.EventSchema) {
		t.Errorf("SupportsSchemas(%q) = false, want true", qlog.EventSchema)
	}
	if trace.SupportsSchemas("urn:ietf:params:qlog:events:http3-12") {
		t.Error("SupportsSchemas() = true for an unrelated schema, want false")
	}
	if trace.AddProducer() == nil {
		t.Error("AddProducer() = nil, want a recorder")
	}
}
