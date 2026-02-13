package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// InstanceAPI APIs for Instance status and version, do not use directly
type InstanceAPI struct {
	c *Client
}

// GetStatus get instance status
// See more: https://docs.netbird.io/api/resources/instance#get-instance-status
func (a *InstanceAPI) GetStatus(ctx context.Context) (*api.InstanceStatus, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/instance", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.InstanceStatus](resp)
	return &ret, err
}

// Setup perform initial instance setup
// See more: https://docs.netbird.io/api/resources/instance#setup-instance
func (a *InstanceAPI) Setup(ctx context.Context, request api.PostApiSetupJSONRequestBody) (*api.SetupResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/setup", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.SetupResponse](resp)
	return &ret, err
}
