package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// PostureChecksAPI APIs for PostureChecks, do not use directly
type PostureChecksAPI struct {
	c *Client
}

// List list all posture checks
// See more: https://docs.netbird.io/api/resources/posture-checks#list-all-posture-checks
func (a *PostureChecksAPI) List(ctx context.Context) ([]api.PostureCheck, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/posture-checks", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.PostureCheck](resp)
	return ret, err
}

// Get get posture check info
// See more: https://docs.netbird.io/api/resources/posture-checks#retrieve-a-posture-check
func (a *PostureChecksAPI) Get(ctx context.Context, postureCheckID string) (*api.PostureCheck, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/posture-checks/"+postureCheckID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.PostureCheck](resp)
	return &ret, err
}

// Create create new posture check
// See more: https://docs.netbird.io/api/resources/posture-checks#create-a-posture-check
func (a *PostureChecksAPI) Create(ctx context.Context, request api.PostApiPostureChecksJSONRequestBody) (*api.PostureCheck, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/posture-checks", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.PostureCheck](resp)
	return &ret, err
}

// Update update posture check info
// See more: https://docs.netbird.io/api/resources/posture-checks#update-a-posture-check
func (a *PostureChecksAPI) Update(ctx context.Context, postureCheckID string, request api.PutApiPostureChecksPostureCheckIdJSONRequestBody) (*api.PostureCheck, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/posture-checks/"+postureCheckID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.PostureCheck](resp)
	return &ret, err
}

// Delete delete posture check
// See more: https://docs.netbird.io/api/resources/posture-checks#delete-a-posture-check
func (a *PostureChecksAPI) Delete(ctx context.Context, postureCheckID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/posture-checks/"+postureCheckID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
