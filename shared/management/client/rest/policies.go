package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// PoliciesAPI APIs for Policies, do not use directly
type PoliciesAPI struct {
	c *Client
}

// List list all policies
// See more: https://docs.netbird.io/api/resources/policies#list-all-policies
func (a *PoliciesAPI) List(ctx context.Context) ([]api.Policy, error) {
	path := "/api/policies"

	resp, err := a.c.NewRequest(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Policy](resp)
	return ret, err
}

// Get get policy info
// See more: https://docs.netbird.io/api/resources/policies#retrieve-a-policy
func (a *PoliciesAPI) Get(ctx context.Context, policyID string) (*api.Policy, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/policies/"+policyID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Policy](resp)
	return &ret, err
}

// Create create new policy
// See more: https://docs.netbird.io/api/resources/policies#create-a-policy
func (a *PoliciesAPI) Create(ctx context.Context, request api.PostApiPoliciesJSONRequestBody) (*api.Policy, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/policies", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Policy](resp)
	return &ret, err
}

// Update update policy info
// See more: https://docs.netbird.io/api/resources/policies#update-a-policy
func (a *PoliciesAPI) Update(ctx context.Context, policyID string, request api.PutApiPoliciesPolicyIdJSONRequestBody) (*api.Policy, error) {
	path := "/api/policies/" + policyID

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", path, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Policy](resp)
	return &ret, err
}

// Delete delete policy
// See more: https://docs.netbird.io/api/resources/policies#delete-a-policy
func (a *PoliciesAPI) Delete(ctx context.Context, policyID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/policies/"+policyID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
