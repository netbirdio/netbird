package link

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util"
)

// credentials carries exactly one proof of identity to the embedded client.
type credentials struct {
	setupKey string
	jwtToken string
}

// resolveCredentials returns a setup key when one was supplied, and otherwise
// drives the interactive login flow.
//
// The embedded client accepts a setup key or an already-issued token, so the
// browser flow is run here and only its result is handed over.
func resolveCredentials(ctx context.Context, cfg *Config) (credentials, error) {
	if cfg.SetupKey != "" {
		log.Info("authenticating with the configured setup key")
		return credentials{setupKey: cfg.SetupKey}, nil
	}

	log.Info("no setup key configured, starting interactive login")
	token, err := interactiveLogin(ctx, cfg)
	if err != nil {
		return credentials{}, err
	}
	return credentials{jwtToken: token}, nil
}

// interactiveLogin runs the standard browser login and returns the token to
// authenticate the peer with.
func interactiveLogin(ctx context.Context, cfg *Config) (string, error) {
	// The flow only needs somewhere to read the management URL from and a key
	// to talk to it with. The peer identity the client ends up using is
	// created separately, so this config is deliberately not persisted.
	flowConfig, err := profilemanager.CreateInMemoryConfig(profilemanager.ConfigInput{
		ManagementURL: cfg.ManagementURL,
	})
	if err != nil {
		return "", fmt.Errorf("prepare login: %w", err)
	}

	flow, err := auth.NewOAuthFlow(ctx, flowConfig, util.HasGraphicalSession(), false, "")
	if err != nil {
		return "", fmt.Errorf("start login: %w", err)
	}

	info, err := flow.RequestAuthInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("request login: %w", err)
	}

	promptLogin(os.Stderr, util.OpenBrowser, info, cfg.NoBrowser)

	token, err := flow.WaitToken(ctx, info)
	if err != nil {
		return "", fmt.Errorf("wait for login: %w", err)
	}

	return token.GetTokenToUse(), nil
}

// promptLogin writes the verification URL to out, which the caller points at
// stderr so stdout stays clean for piping, and opens a browser unless asked not
// to. The URL is always printed so the flow still works over SSH where no
// browser can open.
func promptLogin(out io.Writer, openBrowser func(string) error, info auth.AuthFlowInfo, noBrowser bool) {
	uri := info.VerificationURIComplete
	if uri == "" {
		uri = info.VerificationURI
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\nOpen this URL to log in:\n\n    %s\n", uri)
	if info.UserCode != "" && !strings.Contains(uri, info.UserCode) {
		fmt.Fprintf(&b, "\n    and enter the code %s\n", info.UserCode)
	}
	b.WriteString("\n")
	if _, err := io.WriteString(out, b.String()); err != nil {
		log.Warnf("print login URL: %v", err)
	}

	if noBrowser {
		return
	}
	if err := openBrowser(uri); err != nil {
		log.Debugf("could not open a browser: %v", err)
	}
}
