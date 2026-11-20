package proxy

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
)

type synMappingsProxyClient struct {
	proto.ProxyServiceClient
}

func (synMappingsProxyClient) SendStatusUpdate(context.Context, *proto.SendStatusUpdateRequest, ...grpc.CallOption) (*proto.SendStatusUpdateResponse, error) {
	return &proto.SendStatusUpdateResponse{}, nil
}

func (synMappingsProxyClient) CreateProxyPeer(context.Context, *proto.CreateProxyPeerRequest, ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

func Test_ProcessMapping_HandleDisabledMappings(t *testing.T) {

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)

	l := quietLifecycleLogger()
	srv := &Server{
		Logger:       l,
		mgmtClient:   synMappingsProxyClient{},
		meter:        meter,
		mainPort:     8443,
		portRouters:  make(map[uint16]*portRouter),
		svcPorts:     make(map[types.ServiceID][]uint16),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		proxy:        proxy.NewReverseProxy(nil, "", nil, l),
		auth:         auth.NewMiddleware(l, nil, nil),
		mainRouter:   tcp.NewRouter(l, nil, nil),
		netbird: roundtrip.NewNetBirdForTesting(
			context.Background(),
			"proxy-test",
			"proxy.example.com",
			roundtrip.ClientConfig{},
			l,
			noopNotifier{},
			synMappingsProxyClient{},
			func(_ types.AccountID, _ *embed.Client) {}, // used to skip client startup when a new proxy mapping is created
		),
	}

	{
		// mapping created with disabled field set to true
		srv.portRouters[2222] = &portRouter{router: &tcp.Router{}}

		assert.Empty(t, srv.lastMappings)
		srv.processMappings(context.Background(), []*proto.ProxyMapping{
			{
				Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:         "svc-tcp",
				AccountId:  "acct-1",
				Domain:     "ssh.example.com",
				Mode:       "tcp",
				ListenPort: int32(2222),
				Path: []*proto.PathMapping{
					{Target: "10.0.0.5:22"},
				},
				Disabled: true,
			},
		})
		assert.Nil(t, srv.lastMappings["svc-tcp"])
	}

	tests := []struct {
		description string
		mapping     *proto.ProxyMapping
		change      proto.ProxyMappingUpdateType
		disabled    bool
	}{
		{
			description: "mapping removed",
			change:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
			mapping: &proto.ProxyMapping{
				Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:         "svc-tcp-3333",
				AccountId:  "acct-1",
				Domain:     "ssh.example.com",
				Mode:       "tcp",
				ListenPort: int32(3333),
				Path: []*proto.PathMapping{
					{Target: "10.0.0.5:22"},
				},
				Disabled: false,
			},
		},
		{
			description: "mapping modified with disabled field set to true",
			disabled:    true,
			change:      proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED,
			mapping: &proto.ProxyMapping{
				Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:         "svc-tcp-4444",
				AccountId:  "acct-1",
				Domain:     "ssh.example.com",
				Mode:       "tcp",
				ListenPort: int32(4444),
				Path: []*proto.PathMapping{
					{Target: "10.0.0.5:22"},
				},
				Disabled: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			srv.portRouters[uint16(tt.mapping.ListenPort)] = &portRouter{router: tcp.NewRouter(l, nil, nil)}
			assert.Nil(t, srv.lastMappings[types.ServiceID(tt.mapping.Id)])

			srv.processMappings(context.Background(), []*proto.ProxyMapping{tt.mapping})

			assert.NotNil(t, srv.lastMappings[types.ServiceID(tt.mapping.Id)])

			tt.mapping.Type = tt.change
			tt.mapping.Disabled = tt.disabled
			srv.processMappings(context.Background(), []*proto.ProxyMapping{tt.mapping})

			assert.Nil(t, srv.lastMappings[types.ServiceID(tt.mapping.Id)])
		})
	}
}
