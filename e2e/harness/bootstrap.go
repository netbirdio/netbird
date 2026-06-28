//go:build e2e

package harness

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Bootstrap creates the initial admin owner through the unauthenticated
// /api/setup endpoint and returns the plaintext admin PAT. It also wires an
// authenticated REST client on the Combined (see API). create_pat requires the
// server to run with NB_SETUP_PAT_ENABLED=true, which the harness sets. A
// second call returns an error (the server reports setup already completed).
func (c *Combined) Bootstrap(ctx context.Context) (string, error) {
	// The setup endpoint is unauthenticated; use a tokenless client.
	setupClient := rest.NewWithOptions(rest.WithManagementURL(c.BaseURL))

	createPAT := true
	expireDays := 1
	resp, err := setupClient.Instance.Setup(ctx, api.PostApiSetupJSONRequestBody{
		Email:       "admin@netbird.test",
		Password:    "Netbird-e2e-Passw0rd!",
		Name:        "E2E Admin",
		CreatePat:   &createPAT,
		PatExpireIn: &expireDays,
	})
	if err != nil {
		return "", fmt.Errorf("instance setup: %w", err)
	}
	if resp.PersonalAccessToken == nil || *resp.PersonalAccessToken == "" {
		return "", fmt.Errorf("setup succeeded but no PAT returned (is NB_SETUP_PAT_ENABLED set?)")
	}

	c.PAT = *resp.PersonalAccessToken
	c.api = rest.New(c.BaseURL, c.PAT)
	return c.PAT, nil
}

// API returns the PAT-authenticated management REST client. It is nil until
// Bootstrap runs.
func (c *Combined) API() *rest.Client {
	return c.api
}
