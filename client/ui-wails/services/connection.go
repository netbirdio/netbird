//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"

	"github.com/netbirdio/netbird/client/proto"
)

// LoginParams carries the fields the UI sets when starting a login.
type LoginParams struct {
	ProfileName   string `json:"profileName"`
	Username      string `json:"username"`
	ManagementURL string `json:"managementUrl"`
	SetupKey      string `json:"setupKey"`
	PreSharedKey  string `json:"preSharedKey"`
	Hostname      string `json:"hostname"`
	Hint          string `json:"hint"`
}

// LoginResult is the daemon's reply to a Login call.
type LoginResult struct {
	NeedsSSOLogin           bool   `json:"needsSsoLogin"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
}

// WaitSSOParams carries the fields the UI passes to WaitSSOLogin.
type WaitSSOParams struct {
	UserCode string `json:"userCode"`
	Hostname string `json:"hostname"`
}

// UpParams selects the profile the daemon should bring up.
type UpParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// LogoutParams selects the profile the daemon should log out.
type LogoutParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Connection groups the daemon RPCs that drive login / connect / disconnect.
type Connection struct {
	conn DaemonConn
}

func NewConnection(conn DaemonConn) *Connection {
	return &Connection{conn: conn}
}

func (s *Connection) Login(ctx context.Context, p LoginParams) (LoginResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return LoginResult{}, err
	}

	// Reset the daemon's connection loop before kicking off a new login.
	// If a previous Login left a WaitSSOLogin pending (user closed the
	// browser without completing the flow), the daemon stays parked on the
	// old UserCode and replies with "invalid setup-key or no sso information
	// provided" to a fresh Login. Calling Down first dislodges that state;
	// we ignore the error since Down on an already-idle daemon is a no-op.
	if _, derr := cli.Down(ctx, &proto.DownRequest{}); derr != nil {
		// Down failed — likely because the daemon is already idle. Continue.
		_ = derr
	}

	// Mirror the Fyne client's defaulting: when the frontend doesn't supply
	// profile / username, fall back to the daemon's active profile and the
	// current OS user. The flag matches the Fyne ui's IsUnixDesktopClient
	// condition so the daemon knows we can render an SSO browser flow.
	profileName := p.ProfileName
	username := p.Username
	if profileName == "" {
		if active, aerr := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{}); aerr == nil {
			profileName = active.GetProfileName()
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
		IsUnixDesktopClient: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
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
		return LoginResult{}, err
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
		return "", err
	}
	return resp.GetEmail(), nil
}

func (s *Connection) Up(ctx context.Context, p UpParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.UpRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	_, err = cli.Up(ctx, req)
	return err
}

func (s *Connection) Down(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.Down(ctx, &proto.DownRequest{})
	return err
}

// OpenURL launches the user's preferred browser to display url. Mirrors the
// Fyne client's openURL helper so the SSO flow can pop the verification page
// the same way as the legacy UI — WebKitGTK's window.open is blocked by the
// embedded webview, and asking the user to copy/paste defeats the point of
// SSO. Honors $BROWSER first, then falls back to the platform default.
func (s *Connection) OpenURL(url string) error {
	if browser := os.Getenv("BROWSER"); browser != "" {
		return exec.Command(browser, url).Start()
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux", "freebsd":
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
	_, err = cli.Logout(ctx, req)
	return err
}
