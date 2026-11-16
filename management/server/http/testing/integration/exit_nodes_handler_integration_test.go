//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func serveExitNodes(t *testing.T, handler http.Handler, method, path, user string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		require.NoError(t, err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, testing_tools.BuildRequest(t, raw, method, path, user))
	return recorder
}

func decodeExitNode(t *testing.T, recorder *httptest.ResponseRecorder) api.ExitNode {
	t.Helper()
	require.Equal(t, http.StatusOK, recorder.Code, "status code, body: %s", recorder.Body.String())
	var node api.ExitNode
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &node))
	return node
}

func ptr[T any](v T) *T {
	return &v
}

func Test_ExitNodes_Permissions(t *testing.T) {
	users := []struct {
		name       string
		userId     string
		wantStatus int
	}{
		{"Regular user", testing_tools.TestUserId, http.StatusForbidden},
		{"Admin user", testing_tools.TestAdminId, http.StatusOK},
		{"Owner user", testing_tools.TestOwnerId, http.StatusOK},
		// Exit nodes share the routes permission module, which lets a regular
		// service user read, exactly as GET /api/routes does.
		{"Regular service user", testing_tools.TestServiceUserId, http.StatusOK},
		{"Admin service user", testing_tools.TestServiceAdminId, http.StatusOK},
	}

	for _, user := range users {
		t.Run(user.name, func(t *testing.T) {
			apiHandler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, false)

			recorder := serveExitNodes(t, apiHandler, http.MethodGet, "/api/exit-nodes", user.userId, nil)
			assert.Equal(t, user.wantStatus, recorder.Code, "status code, body: %s", recorder.Body.String())
		})
	}
}

// Test_ExitNodes_Lifecycle runs create, list, update and delete against the
// real store. routes.sql holds a domain route stored with a 0.0.0.0/0 network
// on peerGroupId, which must not count as an exit route.
func Test_ExitNodes_Lifecycle(t *testing.T) {
	// No peer may receive a network map update: exit nodes do not reach clients yet.
	apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/routes.sql", nil, true)
	admin := testing_tools.TestAdminId

	created := decodeExitNode(t, serveExitNodes(t, apiHandler, http.MethodPost, "/api/exit-nodes", admin, api.ExitNodeRequest{
		Name:         "office",
		Description:  ptr("office uplink"),
		Enabled:      true,
		RoutingPeers: []api.ExitNodeRoutingPeerRequest{{PeerGroups: ptr([]string{"peerGroupId"}), Metric: 10, Enabled: true}},
		Masquerade:   true,
		Groups:       []string{"testGroupId"},
		AutoApply:    true,
	}))
	require.NotEmpty(t, created.Id, "exit node id")
	require.Len(t, created.RoutingPeers, 1, "routing peers")
	routingPeerID := created.RoutingPeers[0].Id
	require.NotEmpty(t, routingPeerID, "routing peer id")
	assert.Equal(t, "office", created.Name)
	assert.Equal(t, "office uplink", created.Description)
	assert.Equal(t, []string{"peerGroupId"}, *created.RoutingPeers[0].PeerGroups)
	assert.Equal(t, []string{"testGroupId"}, created.Groups)
	assert.Equal(t, []string{}, created.AccessControlGroups)

	// testPeerId is a member of peerGroupId, so it already serves 0.0.0.0/0.
	conflict := serveExitNodes(t, apiHandler, http.MethodPost, "/api/exit-nodes", admin, api.ExitNodeRequest{
		Name:         "lab",
		RoutingPeers: []api.ExitNodeRoutingPeerRequest{{Peer: ptr(testing_tools.TestPeerId), Metric: 10, Enabled: true}},
		Groups:       []string{"testGroupId"},
	})
	assert.Equal(t, http.StatusConflict, conflict.Code, "a peer serving another exit node, body: %s", conflict.Body.String())

	listed := serveExitNodes(t, apiHandler, http.MethodGet, "/api/exit-nodes", admin, nil)
	require.Equal(t, http.StatusOK, listed.Code)
	var nodes []api.ExitNode
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &nodes))
	require.Len(t, nodes, 1, "only the created exit node should be listed")
	assert.Equal(t, created.Id, nodes[0].Id)

	updated := decodeExitNode(t, serveExitNodes(t, apiHandler, http.MethodPut, "/api/exit-nodes/"+created.Id, admin, api.ExitNodeRequest{
		Name:         "office-renamed",
		Enabled:      false,
		RoutingPeers: []api.ExitNodeRoutingPeerRequest{{Id: ptr(routingPeerID), PeerGroups: ptr([]string{"peerGroupId"}), Metric: 5, Enabled: true}},
		Groups:       []string{"testGroupId", "newGroupId"},
	}))
	assert.Equal(t, created.Id, updated.Id, "the exit node id must not change")
	require.Len(t, updated.RoutingPeers, 1)
	assert.Equal(t, routingPeerID, updated.RoutingPeers[0].Id, "the routing peer entry should keep its id")
	assert.Equal(t, 5, updated.RoutingPeers[0].Metric)
	assert.Equal(t, "office-renamed", updated.Name)
	assert.False(t, updated.Enabled, "enabled")
	assert.Empty(t, updated.Description, "description should be cleared")

	fetched := decodeExitNode(t, serveExitNodes(t, apiHandler, http.MethodGet, "/api/exit-nodes/"+created.Id, admin, nil))
	assert.Equal(t, updated, fetched, "a read should return what the update stored")

	deleted := serveExitNodes(t, apiHandler, http.MethodDelete, "/api/exit-nodes/"+created.Id, admin, nil)
	require.Equal(t, http.StatusOK, deleted.Code, "body: %s", deleted.Body.String())
	gone := serveExitNodes(t, apiHandler, http.MethodGet, "/api/exit-nodes/"+created.Id, admin, nil)
	assert.Equal(t, http.StatusNotFound, gone.Code, "a deleted exit node should not be found")

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("timeout waiting for peerShouldNotReceiveUpdate")
	}
}
