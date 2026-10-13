package link

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/auth"
)

// browserSpy records the URLs a login prompt tried to open.
type browserSpy struct {
	opened []string
	err    error
}

func (b *browserSpy) open(uri string) error {
	b.opened = append(b.opened, uri)
	return b.err
}

func TestPromptLoginPrintsURLAndOpensBrowser(t *testing.T) {
	var out strings.Builder
	browser := &browserSpy{}
	info := auth.AuthFlowInfo{VerificationURIComplete: "https://login.example/device?code=ABCD-EFGH", UserCode: "ABCD-EFGH"}

	promptLogin(&out, browser.open, info, false)

	assert.Contains(t, out.String(), info.VerificationURIComplete, "the URL must be printed")
	assert.NotContains(t, out.String(), "enter the code", "a code already in the URL must not be repeated")
	assert.Equal(t, []string{info.VerificationURIComplete}, browser.opened, "the browser must be opened on the same URL")
}

func TestPromptLoginNoBrowserStillPrintsURL(t *testing.T) {
	var out strings.Builder
	browser := &browserSpy{}
	info := auth.AuthFlowInfo{VerificationURI: "https://login.example/device", UserCode: "WXYZ-1234"}

	promptLogin(&out, browser.open, info, true)

	assert.Contains(t, out.String(), "https://login.example/device", "the URL must be printed even without a browser")
	assert.Contains(t, out.String(), "enter the code WXYZ-1234", "a code missing from the URL must be printed")
	assert.Empty(t, browser.opened, "--no-browser must not open a browser")
}

func TestPromptLoginSurvivesBrowserFailure(t *testing.T) {
	var out strings.Builder
	browser := &browserSpy{err: errors.New("no display")}
	info := auth.AuthFlowInfo{VerificationURIComplete: "https://login.example/authorize"}

	promptLogin(&out, browser.open, info, false)

	assert.Contains(t, out.String(), "https://login.example/authorize",
		"the URL must be printed so the login still works where no browser opens")
}

func TestResolveCredentialsUsesSetupKeyWithoutLogin(t *testing.T) {
	// An unroutable management URL: a login attempt would fail, so success
	// proves the setup key path never starts one.
	cfg := &Config{SetupKey: "11111111-2222-3333-4444-555555555555", ManagementURL: "https://management.invalid"}

	creds, err := resolveCredentials(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, cfg.SetupKey, creds.setupKey, "the configured key must be used")
	assert.Empty(t, creds.jwtToken, "exactly one proof of identity must be handed over")
}
