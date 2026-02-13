package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// PeersAPI APIs for peers, do not use directly
type PeersAPI struct {
	c *Client
}

// PeersListOption options for Peers List API
type PeersListOption func() (string, string)

func PeerNameFilter(name string) PeersListOption {
	return func() (string, string) {
		return "name", name
	}
}

func PeerIPFilter(ip string) PeersListOption {
	return func() (string, string) {
		return "ip", ip
	}
}

// List list all peers
// See more: https://docs.netbird.io/api/resources/peers#list-all-peers
func (a *PeersAPI) List(ctx context.Context, opts ...PeersListOption) ([]api.Peer, error) {
	query := make(map[string]string)
	for _, o := range opts {
		k, v := o()
		query[k] = v
	}
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers", nil, query)
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
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+peerID, nil, nil)
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
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/peers/"+peerID, bytes.NewReader(requestBytes), nil)
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
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/peers/"+peerID, nil, nil)
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
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+peerID+"/accessible-peers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Peer](resp)
	return ret, err
}

// CreateTemporaryAccess create temporary access for a peer
// See more: https://docs.netbird.io/api/resources/peers#create-temporary-access
func (a *PeersAPI) CreateTemporaryAccess(ctx context.Context, peerID string, request api.PostApiPeersPeerIdTemporaryAccessJSONRequestBody) (*api.PeerTemporaryAccessResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/peers/"+peerID+"/temporary-access", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.PeerTemporaryAccessResponse](resp)
	return &ret, err
}

// PeerIngressPortsAPI APIs for Peer Ingress Ports, do not use directly
type PeerIngressPortsAPI struct {
	c      *Client
	peerID string
}

// IngressPorts APIs for peer ingress ports
func (a *PeersAPI) IngressPorts(peerID string) *PeerIngressPortsAPI {
	return &PeerIngressPortsAPI{
		c:      a.c,
		peerID: peerID,
	}
}

// List list all ingress port allocations for a peer
// See more: https://docs.netbird.io/api/resources/peers#list-all-ingress-port-allocations
func (a *PeerIngressPortsAPI) List(ctx context.Context) ([]api.IngressPortAllocation, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+a.peerID+"/ingress/ports", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IngressPortAllocation](resp)
	return ret, err
}

// Get get ingress port allocation info
// See more: https://docs.netbird.io/api/resources/peers#retrieve-an-ingress-port-allocation
func (a *PeerIngressPortsAPI) Get(ctx context.Context, allocationID string) (*api.IngressPortAllocation, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+a.peerID+"/ingress/ports/"+allocationID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPortAllocation](resp)
	return &ret, err
}

// Create create new ingress port allocation
// See more: https://docs.netbird.io/api/resources/peers#create-an-ingress-port-allocation
func (a *PeerIngressPortsAPI) Create(ctx context.Context, request api.PostApiPeersPeerIdIngressPortsJSONRequestBody) (*api.IngressPortAllocation, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/peers/"+a.peerID+"/ingress/ports", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPortAllocation](resp)
	return &ret, err
}

// Update update ingress port allocation
// See more: https://docs.netbird.io/api/resources/peers#update-an-ingress-port-allocation
func (a *PeerIngressPortsAPI) Update(ctx context.Context, allocationID string, request api.PutApiPeersPeerIdIngressPortsAllocationIdJSONRequestBody) (*api.IngressPortAllocation, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/peers/"+a.peerID+"/ingress/ports/"+allocationID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IngressPortAllocation](resp)
	return &ret, err
}

// Delete delete ingress port allocation
// See more: https://docs.netbird.io/api/resources/peers#delete-an-ingress-port-allocation
func (a *PeerIngressPortsAPI) Delete(ctx context.Context, allocationID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/peers/"+a.peerID+"/ingress/ports/"+allocationID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// PeerJobsAPI APIs for Peer Jobs, do not use directly
type PeerJobsAPI struct {
	c      *Client
	peerID string
}

// Jobs APIs for peer jobs
func (a *PeersAPI) Jobs(peerID string) *PeerJobsAPI {
	return &PeerJobsAPI{
		c:      a.c,
		peerID: peerID,
	}
}

// List list all jobs for a peer
// See more: https://docs.netbird.io/api/resources/peers#list-all-peer-jobs
func (a *PeerJobsAPI) List(ctx context.Context) ([]api.JobResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+a.peerID+"/jobs", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.JobResponse](resp)
	return ret, err
}

// Get get job info
// See more: https://docs.netbird.io/api/resources/peers#retrieve-a-peer-job
func (a *PeerJobsAPI) Get(ctx context.Context, jobID string) (*api.JobResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/"+a.peerID+"/jobs/"+jobID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.JobResponse](resp)
	return &ret, err
}

// Create create new job for a peer
// See more: https://docs.netbird.io/api/resources/peers#create-a-peer-job
func (a *PeerJobsAPI) Create(ctx context.Context, request api.PostApiPeersPeerIdJobsJSONRequestBody) (*api.JobResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/peers/"+a.peerID+"/jobs", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.JobResponse](resp)
	return &ret, err
}
