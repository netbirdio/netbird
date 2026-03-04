package proxy

import (
	"context"
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type mockMappingStream struct {
	grpc.ClientStream
	messages []*proto.GetMappingUpdateResponse
	idx      int
}

func (m *mockMappingStream) Recv() (*proto.GetMappingUpdateResponse, error) {
	if m.idx >= len(m.messages) {
		return nil, io.EOF
	}
	msg := m.messages[m.idx]
	m.idx++
	return msg, nil
}

func (m *mockMappingStream) Header() (metadata.MD, error) {
	return nil, nil //nolint:nilnil
}
func (m *mockMappingStream) Trailer() metadata.MD     { return nil }
func (m *mockMappingStream) CloseSend() error         { return nil }
func (m *mockMappingStream) Context() context.Context { return context.Background() }
func (m *mockMappingStream) SendMsg(any) error        { return nil }
func (m *mockMappingStream) RecvMsg(any) error        { return nil }

func TestHandleMappingStream_SyncCompleteFlag(t *testing.T) {
	checker := health.NewChecker(nil, nil)
	s := &Server{
		Logger:        log.StandardLogger(),
		healthChecker: checker,
	}

	stream := &mockMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{InitialSyncComplete: true},
		},
	}

	syncDone := false
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	assert.NoError(t, err)
	assert.True(t, syncDone, "initial sync should be marked done when flag is set")
}

func TestHandleMappingStream_NoSyncFlagDoesNotMarkDone(t *testing.T) {
	checker := health.NewChecker(nil, nil)
	s := &Server{
		Logger:        log.StandardLogger(),
		healthChecker: checker,
	}

	stream := &mockMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{}, // no sync flag
		},
	}

	syncDone := false
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	assert.NoError(t, err)
	assert.False(t, syncDone, "initial sync should not be marked done without flag")
}

func TestHandleMappingStream_NilHealthChecker(t *testing.T) {
	s := &Server{
		Logger: log.StandardLogger(),
	}

	stream := &mockMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{InitialSyncComplete: true},
		},
	}

	syncDone := false
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	assert.NoError(t, err)
	assert.True(t, syncDone, "sync done flag should be set even without health checker")
}
