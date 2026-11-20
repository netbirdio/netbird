package exitnodes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func validExitNode() *ExitNode {
	return &ExitNode{
		Name:    "EU Egress",
		Enabled: true,
		Peers: []Peer{
			{PeerID: "peer-1", Metric: 100, Enabled: true},
			{PeerID: "peer-2", Metric: 200, Enabled: true},
		},
	}
}

func TestExitNode_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(e *ExitNode)
		wantErr string
	}{
		{name: "valid", mutate: func(e *ExitNode) {}},
		{name: "empty name", mutate: func(e *ExitNode) { e.Name = "" }, wantErr: "name is required"},
		{name: "name at limit", mutate: func(e *ExitNode) { e.Name = strings.Repeat("a", MaxNameLength) }},
		{name: "name too long", mutate: func(e *ExitNode) { e.Name = strings.Repeat("a", MaxNameLength+1) }, wantErr: "at most 40"},
		{name: "no peers", mutate: func(e *ExitNode) { e.Peers = nil }, wantErr: "at least one peer"},
		{name: "empty peer ID", mutate: func(e *ExitNode) { e.Peers[0].PeerID = "" }, wantErr: "peer ID is required"},
		{name: "metric zero", mutate: func(e *ExitNode) { e.Peers[0].Metric = 0 }, wantErr: "between 1 and 9999"},
		{name: "metric above max", mutate: func(e *ExitNode) { e.Peers[0].Metric = 10000 }, wantErr: "between 1 and 9999"},
		{name: "metric bounds", mutate: func(e *ExitNode) { e.Peers[0].Metric, e.Peers[1].Metric = 1, 9999 }},
		{name: "duplicate peer", mutate: func(e *ExitNode) { e.Peers[1].PeerID = "peer-1" }, wantErr: "more than once"},
		{name: "all peers disabled", mutate: func(e *ExitNode) { e.Peers[0].Enabled, e.Peers[1].Enabled = false, false }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validExitNode()
			tt.mutate(e)
			err := e.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr, "error should explain the rule")
		})
	}
}

func TestExitNode_FromAPIRequestTrimsName(t *testing.T) {
	description := "egress"
	req := &api.ExitNodeRequest{
		Name:        "  EU Egress  ",
		Description: &description,
		Enabled:     true,
		AutoApply:   true,
		Peers:       []api.ExitNodePeer{{PeerId: "peer-1", Metric: 100, Enabled: true}},
	}

	var e ExitNode
	e.FromAPIRequest(req)

	assert.Equal(t, "EU Egress", e.Name, "name should be trimmed")
	assert.Equal(t, "egress", e.Description)
	assert.Equal(t, []Peer{{PeerID: "peer-1", Metric: 100, Enabled: true}}, e.Peers)

	whitespace := &api.ExitNodeRequest{Name: "   ", Peers: req.Peers}
	e.FromAPIRequest(whitespace)
	assert.Error(t, e.Validate(), "whitespace-only name should be rejected")
}

func TestExitNode_ToAPIResponse(t *testing.T) {
	e := validExitNode()
	e.ID = "node-1"

	resp := e.ToAPIResponse()

	assert.Equal(t, "node-1", resp.Id)
	require.NotNil(t, resp.Description)
	assert.Equal(t, "", *resp.Description, "description should serialize as empty string")
}
