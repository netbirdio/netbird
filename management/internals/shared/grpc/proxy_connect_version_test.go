package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	versionTestProxyID = "proxy-a"
	versionTestCluster = "cluster.example.com"
	versionTestVersion = "0.60.0"
)

// hangupStream cancels its context on the first Send, emulating a proxy that
// disconnects right after receiving the initial snapshot. The legacy stream
// carries no proxy-to-management messages, so this is the only way for
// GetMappingUpdate to return.
type hangupStream struct {
	recordingStream
	ctx    context.Context
	cancel context.CancelFunc
}

func (s *hangupStream) Send(m *proto.GetMappingUpdateResponse) error {
	s.cancel()
	return s.recordingStream.Send(m)
}

func (s *hangupStream) Context() context.Context { return s.ctx }

// newVersionTestServer wires a server whose proxy manager only accepts a
// Connect carrying versionTestVersion, so a dropped or mangled version fails
// the test as an unexpected call.
func newVersionTestServer(t *testing.T) *ProxyServiceServer {
	t.Helper()
	ctrl := gomock.NewController(t)

	svcMgr := rpservice.NewMockManager(ctrl)
	svcMgr.EXPECT().GetGlobalServices(gomock.Any()).Return(nil, nil)

	proxyMgr := proxy.NewMockManager(ctrl)
	proxyMgr.EXPECT().
		Connect(gomock.Any(), versionTestProxyID, gomock.Any(), versionTestCluster, gomock.Any(), versionTestVersion, gomock.Any(), gomock.Any()).
		Return(&proxy.Proxy{ID: versionTestProxyID, Version: versionTestVersion}, nil)
	proxyMgr.EXPECT().Disconnect(gomock.Any(), versionTestProxyID, gomock.Any()).Return(nil)

	s := newSnapshotTestServer(t, 10)
	s.serviceManager = svcMgr
	s.proxyManager = proxyMgr
	return s
}

func TestSyncMappings_ForwardsProxyVersion(t *testing.T) {
	s := newVersionTestServer(t)

	// The init carries the version, the ack acknowledges the empty snapshot,
	// and the exhausted fake stream then ends the RPC.
	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{
			{Msg: &proto.SyncMappingsRequest_Init{Init: &proto.SyncMappingsInit{
				ProxyId: versionTestProxyID,
				Address: versionTestCluster,
				Version: versionTestVersion,
			}}},
			ackMsg(),
		},
	}

	err := s.SyncMappings(stream)
	require.ErrorContains(t, err, "no more recv messages")
}

func TestGetMappingUpdate_ForwardsProxyVersion(t *testing.T) {
	s := newVersionTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream := &hangupStream{ctx: ctx, cancel: cancel}

	err := s.GetMappingUpdate(&proto.GetMappingUpdateRequest{
		ProxyId: versionTestProxyID,
		Address: versionTestCluster,
		Version: versionTestVersion,
	}, stream)
	require.ErrorIs(t, err, context.Canceled)
}
