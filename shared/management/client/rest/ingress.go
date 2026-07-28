package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// IngressAPI APIs for Ingress Peers, do not use directly
type IngressAPI struct {
	c *Client
}

// List all ingress peers
// See more: https://docs.netbird.io/api/resources/ingress#list-all-ingress-peers
func (a *IngressAPI) List(ctx context.Context) ([]api.IngressPeer, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/ingress/peers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IngressPeer](resp)
	return ret, err
}

// Get ingress peer info
// See more: https://docs.netbird.io/api/resources/ingress#retrieve-an-ingress-peer
func (a *IngressAPI) Get(ctx context.Context, ingressPeerID string) (*api.IngressPeer, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/ingress/peers/"+ingressPeerID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPeer](resp)
	return &ret, err
}

// Create new ingress peer
// See more: https://docs.netbird.io/api/resources/ingress#create-an-ingress-peer
func (a *IngressAPI) Create(ctx context.Context, request api.PostApiIngressPeersJSONRequestBody) (*api.IngressPeer, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/ingress/peers", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPeer](resp)
	return &ret, err
}

// Update update ingress peer
// See more: https://docs.netbird.io/api/resources/ingress#update-an-ingress-peer
func (a *IngressAPI) Update(ctx context.Context, ingressPeerID string, request api.PutApiIngressPeersIngressPeerIdJSONRequestBody) (*api.IngressPeer, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/ingress/peers/"+ingressPeerID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPeer](resp)
	return &ret, err
}

// Delete delete ingress peer
// See more: https://docs.netbird.io/api/resources/ingress#delete-an-ingress-peer
func (a *IngressAPI) Delete(ctx context.Context, ingressPeerID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/ingress/peers/"+ingressPeerID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
