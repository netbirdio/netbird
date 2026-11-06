package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	nbstatus "github.com/netbirdio/netbird/shared/management/status"
)

// fakeAgentNetworkInfo records which peer it was asked about, so the test
// can prove the handler resolves the peer from its key and nothing else.
type fakeAgentNetworkInfo struct {
	accountID, peerID string
	info              *types.PeerAgentNetworkInfo
}

func (f *fakeAgentNetworkInfo) GetAgentNetworkInfoForPeer(_ context.Context, accountID, peerID string) (*types.PeerAgentNetworkInfo, error) {
	f.accountID, f.peerID = accountID, peerID
	return f.info, nil
}

func newAgentNetworkInfoTestServer(t *testing.T) (*Server, *account.MockManager, store.Store, wgtypes.Key) {
	t.Helper()
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	accountManager := account.NewMockManager(gomock.NewController(t))
	accountManager.EXPECT().GetStore().Return(s).AnyTimes()

	srv := &Server{
		accountManager: accountManager,
		secretsManager: &TimeBasedAuthSecretsManager{wgKey: serverKey},
	}
	return srv, accountManager, s, serverKey
}

func encryptAgentNetworkInfoRequest(t *testing.T, clientKey, serverKey wgtypes.Key) *proto.EncryptedMessage {
	t.Helper()
	body, err := encryption.EncryptMessage(serverKey.PublicKey(), clientKey, &proto.GetAgentNetworkInfoRequest{})
	require.NoError(t, err)
	return &proto.EncryptedMessage{WgPubKey: clientKey.PublicKey().String(), Body: body}
}

func TestGetAgentNetworkInfo_UnknownPeerKey(t *testing.T) {
	srv, accountManager, _, serverKey := newAgentNetworkInfoTestServer(t)
	srv.SetAgentNetworkInfoService(&fakeAgentNetworkInfo{})

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	accountManager.EXPECT().GetAccountIDForPeerKey(gomock.Any(), clientKey.PublicKey().String()).
		Return("", nbstatus.Errorf(nbstatus.NotFound, "peer not found"))

	_, err = srv.GetAgentNetworkInfo(context.Background(), encryptAgentNetworkInfoRequest(t, clientKey, serverKey))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "unknown peer key must be denied")
}

func TestGetAgentNetworkInfo_UnsetServiceIsUnimplemented(t *testing.T) {
	srv, _, _, serverKey := newAgentNetworkInfoTestServer(t)

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	_, err = srv.GetAgentNetworkInfo(context.Background(), encryptAgentNetworkInfoRequest(t, clientKey, serverKey))
	assert.Equal(t, codes.Unimplemented, status.Code(err), "clients map Unimplemented to MANAGEMENT_UNSUPPORTED")
}

func TestGetAgentNetworkInfo_EncryptedRoundTrip(t *testing.T) {
	srv, accountManager, s, serverKey := newAgentNetworkInfoTestServer(t)
	ctx := context.Background()

	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	// Postgres enforces the peers -> accounts foreign key.
	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: "acct-1"}))
	require.NoError(t, s.AddPeerToAccount(ctx, &nbpeer.Peer{
		ID:        "peer-1",
		AccountID: "acct-1",
		Key:       clientKey.PublicKey().String(),
		DNSLabel:  "peer-1",
		Status:    &nbpeer.PeerStatus{},
	}))
	accountManager.EXPECT().GetAccountIDForPeerKey(gomock.Any(), clientKey.PublicKey().String()).Return("acct-1", nil)

	windowStart := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	fake := &fakeAgentNetworkInfo{info: &types.PeerAgentNetworkInfo{
		State:        types.PeerAgentNetworkOK,
		UserEmail:    "user@example.com",
		LoginExpired: true,
		Config: &types.AgentConfig{
			Configured: true,
			Endpoint:   "https://violet.eu.proxy.netbird.io",
			Providers: []types.AgentConfigProvider{{
				ID: "prov-1", Name: "OpenAI", CatalogID: "openai_api", APIFlavor: "openai",
				Models: []string{"gpt-5.4"},
				Allowance: &types.ProviderAllowance{
					Exhausted: true, ExhaustedReason: "user budget cap exhausted",
					Limits: []types.AllowanceLimit{{
						Source: types.AllowanceSourcePolicy, SourceID: "pol-1", SourceName: "Engineers",
						Unit: types.AllowanceUnitUSD, Scope: types.AllowanceScopeUser,
						Cap: 5, Used: 5.5, WindowSeconds: 86400, WindowStart: windowStart,
						ResetsAt: windowStart.Add(24 * time.Hour),
					}},
				},
			}},
		},
	}}
	srv.SetAgentNetworkInfoService(fake)

	encResp, err := srv.GetAgentNetworkInfo(ctx, encryptAgentNetworkInfoRequest(t, clientKey, serverKey))
	require.NoError(t, err)
	assert.Equal(t, "peer-1", fake.peerID, "peer must be resolved from its key")
	assert.Equal(t, "acct-1", fake.accountID)

	resp := &proto.GetAgentNetworkInfoResponse{}
	require.NoError(t, encryption.DecryptMessage(serverKey.PublicKey(), clientKey, encResp.Body, resp))
	assert.Equal(t, proto.GetAgentNetworkInfoResponse_OK, resp.State)
	assert.Equal(t, "user@example.com", resp.UserEmail)
	assert.True(t, resp.LoginExpired)
	assert.Equal(t, "https://violet.eu.proxy.netbird.io", resp.Endpoint)
	assert.NotNil(t, resp.ComputedAt, "computed_at must be set")
	require.Len(t, resp.Providers, 1)
	assert.Equal(t, "prov-1", resp.Providers[0].Id)
	assert.Equal(t, "openai", resp.Providers[0].ApiFlavor)
	assert.Equal(t, []string{"gpt-5.4"}, resp.Providers[0].Models)
	assert.True(t, resp.Providers[0].Exhausted)
	assert.False(t, resp.Providers[0].Unlimited)
	assert.Equal(t, "user budget cap exhausted", resp.Providers[0].ExhaustedReason)
	require.Len(t, resp.Providers[0].Limits, 1)
	l := resp.Providers[0].Limits[0]
	assert.Equal(t, proto.AgentNetworkLimit_POLICY, l.Source)
	assert.Equal(t, "pol-1", l.SourceId)
	assert.Equal(t, "Engineers", l.SourceName)
	assert.Equal(t, proto.AgentNetworkLimit_USD, l.Unit)
	assert.Equal(t, proto.AgentNetworkLimit_USER, l.Scope)
	assert.Equal(t, 5.0, l.Cap)
	assert.Equal(t, 5.5, l.Used)
	assert.Equal(t, int64(86400), l.WindowSeconds)
	assert.Equal(t, windowStart, l.WindowStart.AsTime())
	assert.Equal(t, windowStart.Add(24*time.Hour), l.ResetsAt.AsTime())
}
