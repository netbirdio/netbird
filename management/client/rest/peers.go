package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// PeersAPI APIs for peers, do not use directly
type PeersAPI struct {
	c *Client
}

// List list all peers
// See more: https://docs.netbird.io/api/resources/peers#list-all-peers
func (a *PeersAPI) List(ctx context.Context) ([]api.Peer, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Peer](resp)
	return ret, err
}

// Get retrieve a peer
// See more: https://docs.netbird.io/api/resources/peers#retrieve-a-peer
func (a *PeersAPI) Get(ctx context.Context, peerID string) (*api.Peer, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+peerID, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Peer](resp)
	return &ret, err
}

// Update update information for a peer
// See more: https://docs.netbird.io/api/resources/peers#update-a-peer
func (a *PeersAPI) Update(ctx context.Context, peerID string, request api.PutApiPeersPeerIdJSONRequestBody) (*api.Peer, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/peers/"+peerID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Peer](resp)
	return &ret, err
}

// Delete delete a peer
// See more: https://docs.netbird.io/api/resources/peers#delete-a-peer
func (a *PeersAPI) Delete(ctx context.Context, peerID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/peers/"+peerID, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListAccessiblePeers list all peers that the specified peer can connect to within the network
// See more: https://docs.netbird.io/api/resources/peers#list-accessible-peers
func (a *PeersAPI) ListAccessiblePeers(ctx context.Context, peerID string) ([]api.Peer, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+peerID+"/accessible-peers", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Peer](resp)
	return ret, err
}
