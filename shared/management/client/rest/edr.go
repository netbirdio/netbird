package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// EDRAPI APIs for EDR integrations (Intune, SentinelOne, Falcon, Huntress)
type EDRAPI struct {
	c *Client
}

// GetIntuneIntegration retrieves the EDR Intune integration
// See more: https://docs.netbird.io/api/resources/edr#get-intune-integration
func (a *EDRAPI) GetIntuneIntegration(ctx context.Context) (*api.EDRIntuneResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/edr/intune", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRIntuneResponse](resp)
	return &ret, err
}

// CreateIntuneIntegration creates a new EDR Intune integration
// See more: https://docs.netbird.io/api/resources/edr#create-intune-integration
func (a *EDRAPI) CreateIntuneIntegration(ctx context.Context, request api.EDRIntuneRequest) (*api.EDRIntuneResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/edr/intune", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRIntuneResponse](resp)
	return &ret, err
}

// UpdateIntuneIntegration updates an existing EDR Intune integration
// See more: https://docs.netbird.io/api/resources/edr#update-intune-integration
func (a *EDRAPI) UpdateIntuneIntegration(ctx context.Context, request api.EDRIntuneRequest) (*api.EDRIntuneResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/edr/intune", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRIntuneResponse](resp)
	return &ret, err
}

// DeleteIntuneIntegration deletes the EDR Intune integration
// See more: https://docs.netbird.io/api/resources/edr#delete-intune-integration
func (a *EDRAPI) DeleteIntuneIntegration(ctx context.Context) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/edr/intune", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// GetSentinelOneIntegration retrieves the EDR SentinelOne integration
// See more: https://docs.netbird.io/api/resources/edr#get-sentinelone-integration
func (a *EDRAPI) GetSentinelOneIntegration(ctx context.Context) (*api.EDRSentinelOneResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/edr/sentinelone", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRSentinelOneResponse](resp)
	return &ret, err
}

// CreateSentinelOneIntegration creates a new EDR SentinelOne integration
// See more: https://docs.netbird.io/api/resources/edr#create-sentinelone-integration
func (a *EDRAPI) CreateSentinelOneIntegration(ctx context.Context, request api.EDRSentinelOneRequest) (*api.EDRSentinelOneResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/edr/sentinelone", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRSentinelOneResponse](resp)
	return &ret, err
}

// UpdateSentinelOneIntegration updates an existing EDR SentinelOne integration
// See more: https://docs.netbird.io/api/resources/edr#update-sentinelone-integration
func (a *EDRAPI) UpdateSentinelOneIntegration(ctx context.Context, request api.EDRSentinelOneRequest) (*api.EDRSentinelOneResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/edr/sentinelone", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRSentinelOneResponse](resp)
	return &ret, err
}

// DeleteSentinelOneIntegration deletes the EDR SentinelOne integration
// See more: https://docs.netbird.io/api/resources/edr#delete-sentinelone-integration
func (a *EDRAPI) DeleteSentinelOneIntegration(ctx context.Context) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/edr/sentinelone", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// GetFalconIntegration retrieves the EDR Falcon integration
// See more: https://docs.netbird.io/api/resources/edr#get-falcon-integration
func (a *EDRAPI) GetFalconIntegration(ctx context.Context) (*api.EDRFalconResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/edr/falcon", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRFalconResponse](resp)
	return &ret, err
}

// CreateFalconIntegration creates a new EDR Falcon integration
// See more: https://docs.netbird.io/api/resources/edr#create-falcon-integration
func (a *EDRAPI) CreateFalconIntegration(ctx context.Context, request api.EDRFalconRequest) (*api.EDRFalconResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/edr/falcon", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRFalconResponse](resp)
	return &ret, err
}

// UpdateFalconIntegration updates an existing EDR Falcon integration
// See more: https://docs.netbird.io/api/resources/edr#update-falcon-integration
func (a *EDRAPI) UpdateFalconIntegration(ctx context.Context, request api.EDRFalconRequest) (*api.EDRFalconResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/edr/falcon", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRFalconResponse](resp)
	return &ret, err
}

// DeleteFalconIntegration deletes the EDR Falcon integration
// See more: https://docs.netbird.io/api/resources/edr#delete-falcon-integration
func (a *EDRAPI) DeleteFalconIntegration(ctx context.Context) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/edr/falcon", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// GetHuntressIntegration retrieves the EDR Huntress integration
// See more: https://docs.netbird.io/api/resources/edr#get-huntress-integration
func (a *EDRAPI) GetHuntressIntegration(ctx context.Context) (*api.EDRHuntressResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/edr/huntress", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRHuntressResponse](resp)
	return &ret, err
}

// CreateHuntressIntegration creates a new EDR Huntress integration
// See more: https://docs.netbird.io/api/resources/edr#create-huntress-integration
func (a *EDRAPI) CreateHuntressIntegration(ctx context.Context, request api.EDRHuntressRequest) (*api.EDRHuntressResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/edr/huntress", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRHuntressResponse](resp)
	return &ret, err
}

// UpdateHuntressIntegration updates an existing EDR Huntress integration
// See more: https://docs.netbird.io/api/resources/edr#update-huntress-integration
func (a *EDRAPI) UpdateHuntressIntegration(ctx context.Context, request api.EDRHuntressRequest) (*api.EDRHuntressResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/edr/huntress", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.EDRHuntressResponse](resp)
	return &ret, err
}

// DeleteHuntressIntegration deletes the EDR Huntress integration
// See more: https://docs.netbird.io/api/resources/edr#delete-huntress-integration
func (a *EDRAPI) DeleteHuntressIntegration(ctx context.Context) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/edr/huntress", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// BypassPeerCompliance bypasses compliance for a non-compliant peer
// See more: https://docs.netbird.io/api/resources/edr#bypass-peer-compliance
func (a *EDRAPI) BypassPeerCompliance(ctx context.Context, peerID string) (*api.BypassResponse, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/peers/"+peerID+"/edr/bypass", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.BypassResponse](resp)
	return &ret, err
}

// RevokePeerBypass revokes the compliance bypass for a peer
// See more: https://docs.netbird.io/api/resources/edr#revoke-peer-bypass
func (a *EDRAPI) RevokePeerBypass(ctx context.Context, peerID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/peers/"+peerID+"/edr/bypass", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// ListBypassedPeers returns all peers that have compliance bypassed
// See more: https://docs.netbird.io/api/resources/edr#list-all-bypassed-peers
func (a *EDRAPI) ListBypassedPeers(ctx context.Context) ([]api.BypassResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/peers/edr/bypassed", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.BypassResponse](resp)
	return ret, err
}
