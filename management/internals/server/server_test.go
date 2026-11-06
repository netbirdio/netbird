package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

type noopEphemeralManager struct{}

func (noopEphemeralManager) LoadInitialPeers(context.Context)                 {}
func (noopEphemeralManager) Stop()                                            {}
func (noopEphemeralManager) OnPeerConnected(context.Context, *nbpeer.Peer)    {}
func (noopEphemeralManager) OnPeerDisconnected(context.Context, *nbpeer.Peer) {}

func newStartTestServer(t *testing.T, liveness peerliveness.Controller) *BaseServer {
	t.Helper()
	t.Setenv(geolocationDisabledKey, "true")

	srv := NewServer(&Config{NbConfig: &nbconfig.Config{
		HttpConfig: &nbconfig.HttpServerConfig{CertFile: "missing.pem", CertKey: "missing.key"},
	}})
	Inject[peers.Manager](srv, peers.NewMockManager(gomock.NewController(t)))
	Inject[telemetry.AppMetrics](srv, &telemetry.MockAppMetrics{ExposeFunc: func(context.Context, int, string) error { return nil }})
	Inject[ephemeral.Manager](srv, noopEphemeralManager{})
	Inject[peerliveness.Controller](srv, liveness)
	return srv
}

func TestStart_ReleasesPeerLivenessWhenBootFailsAfterItStarted(t *testing.T) {
	liveness := peerliveness.NewMockController(gomock.NewController(t))
	liveness.EXPECT().Start(gomock.Any()).Return(nil)
	liveness.EXPECT().Release(gomock.Any()).Return(nil)

	require.ErrorContains(t, newStartTestServer(t, liveness).Start(context.Background()), "missing.pem")
}

func TestStart_DoesNotReleasePeerLivenessWhenItFailsToStart(t *testing.T) {
	liveness := peerliveness.NewMockController(gomock.NewController(t))
	liveness.EXPECT().Start(gomock.Any()).Return(errors.New("boom"))

	require.Error(t, newStartTestServer(t, liveness).Start(context.Background()))
}
