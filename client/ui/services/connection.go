//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// LoginParams are the inputs to Login.
type LoginParams struct {
	ProfileName   string `json:"profileName"`
	Username      string `json:"username"`
	ManagementURL string `json:"managementUrl"`
	SetupKey      string `json:"setupKey"`
	PreSharedKey  string `json:"preSharedKey"`
	Hostname      string `json:"hostname"`
	Hint          string `json:"hint"`
}

// LoginResult is the daemon's reply to Login.
type LoginResult struct {
	NeedsSSOLogin           bool   `json:"needsSsoLogin"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
}

// WaitSSOParams are the inputs to WaitSSOLogin.
type WaitSSOParams struct {
	UserCode string `json:"userCode"`
	Hostname string `json:"hostname"`
}

// UpParams selects the profile to bring up.
type UpParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// LogoutParams selects the profile to log out.
type LogoutParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Connection groups the daemon RPCs that drive login / connect / disconnect.
type Connection struct {
	conn       DaemonConn
	classifier errorClassifier
}

// NewConnection wires up a Connection. translator or prefs may be nil, in which
// case classifyDaemonError falls back to the bare error key.
func NewConnection(conn DaemonConn, translator ErrorTranslator, prefs LanguagePreference) *Connection {
	return &Connection{conn: conn, classifier: errorClassifier{translator: translator, prefs: prefs}}
}

func (s *Connection) Login(ctx context.Context, p LoginParams) (LoginResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return LoginResult{}, err
	}

	// No pre-Login Down: Login dislodges a pending WaitSSOLogin itself, and a
	// defensive Down would only flash an Idle blink in the tray during handoff.

	// Fall back to the daemon's active profile and the current OS user.
	profileName := p.ProfileName
	username := p.Username
	if profileName == "" {
		if active, aerr := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{}); aerr == nil {
			// Address the active profile by ID (the daemon resolves it as a
			// handle); names can collide, the ID cannot.
			profileName = active.GetId()
			if username == "" {
				username = active.GetUsername()
			}
		}
	}
	if username == "" {
		if u, uerr := user.Current(); uerr == nil {
			username = u.Username
		}
	}

	req := &proto.LoginRequest{
		ManagementUrl:       p.ManagementURL,
		SetupKey:            p.SetupKey,
		Hostname:            p.Hostname,
		IsUnixDesktopClient: runtime.GOOS == "linux",
	}
	if profileName != "" {
		req.ProfileName = ptrStr(profileName)
	}
	if username != "" {
		req.Username = ptrStr(username)
	}
	if p.PreSharedKey != "" {
		req.OptionalPreSharedKey = ptrStr(p.PreSharedKey)
	}
	if p.Hint != "" {
		req.Hint = ptrStr(p.Hint)
	}

	resp, err := cli.Login(ctx, req)
	if err != nil {
		return LoginResult{}, s.classifyDaemonError(err)
	}
	return LoginResult{
		NeedsSSOLogin:           resp.GetNeedsSSOLogin(),
		UserCode:                resp.GetUserCode(),
		VerificationURI:         resp.GetVerificationURI(),
		VerificationURIComplete: resp.GetVerificationURIComplete(),
	}, nil
}

func (s *Connection) WaitSSOLogin(ctx context.Context, p WaitSSOParams) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	resp, err := cli.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{
		UserCode: p.UserCode,
		Hostname: p.Hostname,
	})
	if err != nil {
		return "", s.classifyDaemonError(err)
	}
	return resp.GetEmail(), nil
}

func (s *Connection) Up(ctx context.Context, p UpParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	// Always async: status updates flow via SubscribeStatus.
	req := &proto.UpRequest{Async: true}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	if _, err = cli.Up(ctx, req); err != nil {
		return s.classifyDaemonError(err)
	}
	return nil
}

func (s *Connection) Down(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	if _, err = cli.Down(ctx, &proto.DownRequest{}); err != nil {
		return s.classifyDaemonError(err)
	}
	return nil
}

// OpenURL opens url in an external browser; the embedded webview blocks
// window.open, so the SSO verification page can't pop inline. Honors $BROWSER
// before the platform default.
func (s *Connection) OpenURL(url string) error {
	if browser := os.Getenv("BROWSER"); browser != "" {
		return exec.Command(browser, url).Start()
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

func (s *Connection) Logout(ctx context.Context, p LogoutParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.LogoutRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	if _, err = cli.Logout(ctx, req); err != nil {
		return s.classifyDaemonError(err)
	}

	// The daemon runs as root and can't reach the user-owned per-profile state
	// file holding the account email (see Profiles.List), so clear the stale
	// email here; the next SSO login recreates it.
	if p.ProfileName != "" {
		if err := profilemanager.NewProfileManager().RemoveProfileState(p.ProfileName); err != nil {
			// Non-fatal: the logout itself succeeded.
			log.Warnf("failed to remove profile state for %s: %v", p.ProfileName, err)
		}
	}

	return nil
}

// classifyDaemonError maps a gRPC error to a localised ClientError.
func (s *Connection) classifyDaemonError(err error) *ClientError {
	return s.classifier.classify(err)
}
