package manager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db/dbtest"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// newTestRouter serves the API from a real manager and repository, so a test
// sees what the database stored.
func newTestRouter(t *testing.T) *mux.Router {
	t.Helper()
	conn := dbtest.NewConn(t, &exitnodes.ExitNode{}, &exitnodes.Peer{})
	m := NewManager(NewRepository(conn), conn, newTestStore(t), &mock_server.MockAccountManager{}, allowAll(t))
	router := mux.NewRouter()
	RegisterEndpoints(router, m)
	return router
}

func doRequest(t *testing.T, router *mux.Router, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{AccountId: testAccountID, UserId: testUserID})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAPI_ExitNodeLifecycle(t *testing.T) {
	router := newTestRouter(t)

	description := "Internet egress for US teams"
	req := api.ExitNodeRequest{
		Name:        "US Egress",
		Description: &description,
		Enabled:     true,
		AutoApply:   true,
		Peers:       []api.ExitNodePeer{{PeerId: "peer-c", Metric: 100, Enabled: true}},
	}

	rec := doRequest(t, router, http.MethodPost, "/exit-nodes", req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var created api.ExitNode
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.Id)
	assert.Equal(t, "US Egress", created.Name)

	rec = doRequest(t, router, http.MethodGet, "/exit-nodes", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var all []api.ExitNode
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &all))
	require.Len(t, all, 1, "list should hold the created exit node")
	assert.Equal(t, created, all[0], "list should return what create stored")

	req.Enabled = false
	rec = doRequest(t, router, http.MethodPut, "/exit-nodes/"+created.Id, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updated api.ExitNode
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	assert.Equal(t, created.Id, updated.Id)
	assert.False(t, updated.Enabled)

	rec = doRequest(t, router, http.MethodGet, "/exit-nodes/"+created.Id, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got api.ExitNode
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, updated, got, "get should return what update stored")

	rec = doRequest(t, router, http.MethodDelete, "/exit-nodes/"+created.Id, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{}`, rec.Body.String())

	rec = doRequest(t, router, http.MethodGet, "/exit-nodes/"+created.Id, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAPI_ErrorStatusCodes(t *testing.T) {
	router := newTestRouter(t)

	existing := api.ExitNodeRequest{
		Name:    "EU Egress",
		Enabled: true,
		Peers:   []api.ExitNodePeer{{PeerId: "peer-a", Metric: 100, Enabled: true}},
	}
	rec := doRequest(t, router, http.MethodPost, "/exit-nodes", existing)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	valid := func() api.ExitNodeRequest {
		return api.ExitNodeRequest{
			Name:    "US Egress",
			Enabled: true,
			Peers:   []api.ExitNodePeer{{PeerId: "peer-c", Metric: 100, Enabled: true}},
		}
	}

	tests := []struct {
		name   string
		mutate func(r *api.ExitNodeRequest)
		want   int
	}{
		{name: "blank name", mutate: func(r *api.ExitNodeRequest) { r.Name = "  " }, want: http.StatusUnprocessableEntity},
		{name: "metric out of range", mutate: func(r *api.ExitNodeRequest) { r.Peers[0].Metric = 10000 }, want: http.StatusUnprocessableEntity},
		{name: "no peers", mutate: func(r *api.ExitNodeRequest) { r.Peers = nil }, want: http.StatusUnprocessableEntity},
		{name: "duplicate name", mutate: func(r *api.ExitNodeRequest) { r.Name = "eu egress" }, want: http.StatusConflict},
		{name: "peer in another exit node", mutate: func(r *api.ExitNodeRequest) { r.Peers[0].PeerId = "peer-a" }, want: http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid()
			tt.mutate(&req)
			rec := doRequest(t, router, http.MethodPost, "/exit-nodes", req)
			assert.Equal(t, tt.want, rec.Code, rec.Body.String())
		})
	}

	rec = doRequest(t, router, http.MethodPut, "/exit-nodes/unknown", valid())
	assert.Equal(t, http.StatusNotFound, rec.Code, "update of an unknown exit node")

	rec = doRequest(t, router, http.MethodDelete, "/exit-nodes/unknown", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, "delete of an unknown exit node")
}
