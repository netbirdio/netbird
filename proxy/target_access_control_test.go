package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	managementproto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestTargetAccessActionFromProto(t *testing.T) {
	tests := []struct {
		name string
		wire managementproto.TargetAccessAction
		want internalproxy.AccessAction
	}{
		{"inherit", managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_INHERIT, internalproxy.AccessActionInherit},
		{"bypass", managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS, internalproxy.AccessActionBypass},
		{"block", managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK, internalproxy.AccessActionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := targetAccessActionFromProto(tt.wire)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "wire action must retain its enforcement meaning")
		})
	}
	_, err := targetAccessActionFromProto(managementproto.TargetAccessAction(99))
	require.Error(t, err, "an unknown wire action must reject the mapping")
}

func TestProtoToMappingPreservesLegacyDuplicateLocations(t *testing.T) {
	runtime, _ := newTargetAccessRuntime(t)
	mapping, err := runtime.protoToMapping(t.Context(), &managementproto.ProxyMapping{
		Id: "legacy-service", AccountId: "account", Domain: targetAccessDomain,
		Path: []*managementproto.PathMapping{
			{Path: "/", Target: "http://first.internal"},
			{Path: "/", Target: "https://second.internal"},
			{Path: "", Target: "http://empty.internal"},
		},
	})
	require.NoError(t, err)
	require.Len(t, mapping.Paths, 2, "legacy empty and slash locations must remain distinct")
	assert.Equal(t, "second.internal", mapping.Paths["/"].URL.Host,
		"legacy duplicate locations must retain last-entry-wins behavior")
	assert.Equal(t, "empty.internal", mapping.Paths[""].URL.Host)
}

func TestProtoToMappingRejectsDuplicateLocationsWhenAccessControlIsActive(t *testing.T) {
	tests := []struct {
		name  string
		paths []*managementproto.PathMapping
	}{
		{
			name: "duplicate action location",
			paths: []*managementproto.PathMapping{
				{Path: "/", Target: "http://first.internal"},
				{Path: "/", Target: "http://second.internal", AccessAction: managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK},
			},
		},
		{
			name: "root aliases",
			paths: []*managementproto.PathMapping{
				{Path: "", Target: "http://first.internal"},
				{Path: "/", Target: "http://second.internal", AccessAction: managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS},
			},
		},
		{
			name: "action elsewhere",
			paths: []*managementproto.PathMapping{
				{Path: "/", Target: "http://first.internal"},
				{Path: "/", Target: "http://second.internal"},
				{Path: "/public", Target: "http://public.internal", AccessAction: managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, _ := newTargetAccessRuntime(t)
			_, err := runtime.protoToMapping(t.Context(), &managementproto.ProxyMapping{
				Id: "guarded-service", AccountId: "account", Domain: targetAccessDomain, Path: tt.paths,
			})
			assert.ErrorContains(t, err, `duplicate target location "/"`)
		})
	}
}

func TestModifyHTTPMappingRejectsInvalidReplacement(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*managementproto.ProxyMapping)
	}{
		{"unknown action", func(m *managementproto.ProxyMapping) {
			m.Path[0].AccessAction = managementproto.TargetAccessAction(99)
		}},
		{"duplicate locations", func(m *managementproto.ProxyMapping) {
			m.Path = append(m.Path, &managementproto.PathMapping{Path: "/", Target: "http://127.0.0.1:1"})
		}},
		{"duplicate root aliases", func(m *managementproto.ProxyMapping) {
			m.Path = append(m.Path, &managementproto.PathMapping{Target: "http://127.0.0.1:1"})
		}},
		{"nil target", func(m *managementproto.ProxyMapping) {
			m.Path = append(m.Path, nil)
		}},
		{"malformed URL", func(m *managementproto.ProxyMapping) {
			m.Path[0].Target = "http://["
		}},
		{"missing host", func(m *managementproto.ProxyMapping) {
			m.Path[0].Target = "http:/backend"
		}},
		{"unsupported protocol", func(m *managementproto.ProxyMapping) {
			m.Path[0].Target = "ftp://backend"
		}},
		{"private bypass", func(m *managementproto.ProxyMapping) {
			m.Private = true
			m.Path[0].AccessAction = managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS
		}},
		{"agent network bypass", func(m *managementproto.ProxyMapping) {
			m.Path[0].AccessAction = managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS
			m.Path[0].Options = &managementproto.PathTargetOptions{AgentNetwork: true}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, handler := newTargetAccessRuntime(t)
			original := &managementproto.ProxyMapping{
				Id: "guarded-service", AccountId: "account", Domain: targetAccessDomain,
				Path: []*managementproto.PathMapping{{
					Path: "/", Target: "http://127.0.0.1:1",
					AccessAction: managementproto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK,
				}},
			}
			applyTargetAccessMapping(t, runtime, original)
			replacement := proto.Clone(original).(*managementproto.ProxyMapping)
			tt.modify(replacement)
			require.Error(t, runtime.modifyMapping(t.Context(), replacement))
			response := targetAccessRequestTo(handler, "/protected", "192.0.2.1:1234", nil)
			assert.Equal(t, http.StatusNotFound, response.Code,
				"invalid replacement must withdraw the route instead of retaining a stale policy")
			require.NoError(t, runtime.modifyMapping(t.Context(), original),
				"a valid update must reinstall a previously withdrawn route")
			recovered := targetAccessRequestTo(handler, "/protected", "192.0.2.1:1234", nil)
			assert.Equal(t, http.StatusForbidden, recovered.Code, "the reinstalled block must be enforced")
		})
	}
}
