package service

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func validMultiPortService() *Service {
	return &Service{
		ID:         "service-1",
		AccountID:  "account-1",
		Name:       "game",
		Domain:     "game.example.test",
		Mode:       ModeTCP,
		ListenPort: 443,
		Enabled:    true,
		Targets: []*Target{{
			AccountID:  "account-1",
			TargetId:   "peer-1",
			TargetType: TargetTypePeer,
			Host:       "100.64.0.10",
			Port:       443,
			Protocol:   TargetProtoTCP,
			Enabled:    true,
		}},
		PortMappings: []*PortMapping{
			{Protocol: ModeTCP, ListenPortStart: 443, ListenPortEnd: 443, TargetPortStart: 443, TargetPortEnd: 443},
			{Protocol: ModeTCP, ListenPortStart: 25565, ListenPortEnd: 25565, TargetPortStart: 25565, TargetPortEnd: 25565},
			{Protocol: ModeUDP, ListenPortStart: 19132, ListenPortEnd: 19132, TargetPortStart: 19132, TargetPortEnd: 19132},
			{Protocol: ModeUDP, ListenPortStart: 5000, ListenPortEnd: 5030, TargetPortStart: 6000, TargetPortEnd: 6030},
		},
	}
}

func TestValidatePortMappings_MixedProtocolsTranslationAndRanges(t *testing.T) {
	svc := validMultiPortService()
	require.NoError(t, svc.Validate())

	assert.Equal(t, ModeTCP, svc.Mode)
	assert.Equal(t, uint16(443), svc.ListenPort)
	assert.Equal(t, uint16(443), svc.Targets[0].Port)
	assert.Equal(t, TargetProtoTCP, svc.Targets[0].Protocol)
	assert.True(t, svc.RequiresMultiPortCapability())

	// TCP and UDP own separate sockets, so the same numeric listener is valid.
	svc.PortMappings = append(svc.PortMappings,
		&PortMapping{Protocol: ModeUDP, ListenPortStart: 443, ListenPortEnd: 443, TargetPortStart: 7443, TargetPortEnd: 7443})
	require.NoError(t, svc.Validate())
}

func TestValidatePortMappings_InvalidCollections(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Service)
		wantErr string
	}{
		{
			name: "zero port",
			mutate: func(s *Service) {
				s.PortMappings[0].ListenPortStart = 0
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "reversed listener range",
			mutate: func(s *Service) {
				s.PortMappings[0].ListenPortStart = 444

			},
			wantErr: "listener range is reversed",
		},
		{
			name: "reversed target range",
			mutate: func(s *Service) {
				s.PortMappings[0].TargetPortStart = 444
			},
			wantErr: "target range is reversed",
		},
		{
			name: "mismatched sizes",
			mutate: func(s *Service) {
				s.PortMappings[3].TargetPortEnd = 6029
			},
			wantErr: "same number of ports",
		},
		{
			name: "overlapping TCP ranges",
			mutate: func(s *Service) {
				s.PortMappings = append(s.PortMappings, &PortMapping{
					Protocol: ModeTCP, ListenPortStart: 25560, ListenPortEnd: 25570,
					TargetPortStart: 30000, TargetPortEnd: 30010,
				})
			},
			wantErr: "overlaps",
		},
		{
			name: "unsupported protocol",
			mutate: func(s *Service) {
				s.PortMappings[0].Protocol = "http"
			},
			wantErr: "not supported",
		},
		{
			name: "nil mapping",
			mutate: func(s *Service) {
				s.PortMappings[1] = nil
			},
			wantErr: "must not be null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := validMultiPortService()
			tt.mutate(svc)
			assert.ErrorContains(t, svc.Validate(), tt.wantErr)
		})
	}
}

func TestPortMappingsFromAPI_RejectsOutOfBoundsBeforeUint16Conversion(t *testing.T) {
	mode := api.ServiceRequestMode(ModeTCP)
	targets := []api.ServiceTarget{{
		TargetId: "peer-1", TargetType: api.ServiceTargetTargetType(TargetTypePeer),
		Protocol: api.ServiceTargetProtocolTcp, Port: 443, Enabled: true,
	}}

	for _, invalid := range []int{-1, 0, 65536, 100000} {
		t.Run(strconv.Itoa(invalid), func(t *testing.T) {
			mappings := []api.ServicePortMapping{{
				Protocol:        api.ServicePortMappingProtocolTcp,
				ListenPortStart: invalid, ListenPortEnd: 443,
				TargetPortStart: 443, TargetPortEnd: 443,
			}}
			req := &api.ServiceRequest{
				Name: "game", Domain: "game.example.test", Enabled: true,
				Mode: &mode, Targets: &targets, PortMappings: &mappings,
			}
			assert.ErrorContains(t, new(Service).FromAPIRequest(req, "account-1"), "between 1 and 65535")
		})
	}
}

func TestPortMappings_APIRoundTripAndLegacyMirrors(t *testing.T) {
	mode := api.ServiceRequestMode(ModeTCP)
	listenPort := 8080
	targets := []api.ServiceTarget{{
		TargetId: "peer-1", TargetType: api.ServiceTargetTargetType(TargetTypePeer),
		Protocol: api.ServiceTargetProtocolTcp, Port: 18080, Enabled: true,
	}}
	mappings := []api.ServicePortMapping{
		{Protocol: api.ServicePortMappingProtocolTcp, ListenPortStart: 8080, ListenPortEnd: 8080, TargetPortStart: 18080, TargetPortEnd: 18080},
		{Protocol: api.ServicePortMappingProtocolUdp, ListenPortStart: 9000, ListenPortEnd: 9002, TargetPortStart: 19000, TargetPortEnd: 19002},
	}
	req := &api.ServiceRequest{
		Name: "game", Domain: "game.example.test", Enabled: true,
		Mode: &mode, ListenPort: &listenPort, Targets: &targets, PortMappings: &mappings,
	}

	svc := &Service{ID: "service-1"}
	require.NoError(t, svc.FromAPIRequest(req, "account-1"))
	require.NoError(t, svc.Validate())
	assert.True(t, svc.PortMappingsSet)
	assert.Equal(t, uint16(8080), svc.ListenPort)
	assert.Equal(t, uint16(18080), svc.Targets[0].Port)
	assert.Equal(t, TargetProtoTCP, svc.Targets[0].Protocol)

	resp := svc.ToAPIResponse()
	require.NotNil(t, resp.PortMappings)
	assert.Equal(t, mappings, *resp.PortMappings)

	encoded, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.JSONEq(t, `[
		{"protocol":"tcp","listen_port_start":8080,"listen_port_end":8080,"target_port_start":18080,"target_port_end":18080},
		{"protocol":"udp","listen_port_start":9000,"listen_port_end":9002,"target_port_start":19000,"target_port_end":19002}
	]`, string(mustPortMappingsJSON(t, encoded)))
}

func mustPortMappingsJSON(t *testing.T, serviceJSON []byte) json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(serviceJSON, &object))
	return object["port_mappings"]
}

func TestPortMappings_ProtoCompatibility(t *testing.T) {
	legacy := validMultiPortService()
	legacy.PortMappings = legacy.PortMappings[:1]
	require.NoError(t, legacy.Validate())
	assert.False(t, legacy.RequiresMultiPortCapability())
	assert.Empty(t, legacy.ToProtoMapping(Create, "", proxy.OIDCValidationConfig{}).PortMappings,
		"an exact one-port service must remain readable by old proxies")

	multi := validMultiPortService()
	require.NoError(t, multi.Validate())
	wire := multi.ToProtoMapping(Update, "", proxy.OIDCValidationConfig{})
	require.Len(t, wire.PortMappings, 4)
	assert.Equal(t, uint32(5030), wire.PortMappings[3].ListenPortEnd)
	assert.Equal(t, uint32(6000), wire.PortMappings[3].TargetPortStart)
	assert.Equal(t, uint32(6030), wire.PortMappings[3].TargetPortEnd)
}

func TestPortMappings_CopyIsDeepAndPreservesOrder(t *testing.T) {
	svc := validMultiPortService()
	serviceCopy := svc.Copy()
	require.Len(t, serviceCopy.PortMappings, len(svc.PortMappings))
	for i, mapping := range serviceCopy.PortMappings {
		assert.Equal(t, i, mapping.Position)
		assert.Equal(t, svc.ID, mapping.ServiceID)
		assert.Equal(t, svc.AccountID, mapping.AccountID)
	}

	serviceCopy.PortMappings[0].ListenPortStart = 8443
	assert.Equal(t, uint16(443), svc.PortMappings[0].ListenPortStart)
}
