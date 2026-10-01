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
	// ProfileID is the ID of the profile this login ran against, or "" when the
	// caller named the profile itself and no ID was resolved. Pass it back in
	// WaitSSOParams so the account email lands on this profile even if the
	// active one changes during SSO.
	ProfileID string `json:"profileId"`
}

// WaitSSOParams are the inputs to waitSSOLogin.
type WaitSSOParams struct {
	UserCode string `json:"userCode"`
	Hostname string `json:"hostname"`
	// ProfileID is the profile the login was started for, used to file the
	// account email against it rather than against whichever profile is active
	// when the flow returns. Optional: empty falls back to the active profile.
	ProfileID string `json:"profileId"`
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
	// Only set when the daemon told us the ID. A caller-supplied ProfileName is
	// a handle — a display name or an ID prefix resolve too — and the state file
	// is named after the ID, so passing a handle on would name the wrong file.
	profileID := ""
	if profileName == "" {
		if active, aerr := cli.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{}); aerr == nil {
			// Address the active profile by ID (the daemon resolves it as a
			// handle); names can collide, the ID cannot.
			profileName = active.GetId()
			profileID = profileName
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
		ManagementUrl: p.ManagementURL,
		SetupKey:      p.SetupKey,
		Hostname:      p.Hostname,
		// a login driven by the UI always has a graphical session available
		IsUnixDesktopClient: true,
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
	hint := p.Hint
	if hint == "" && profileID != "" {
		if state, serr := profilemanager.NewProfileManager().GetProfileState(profilemanager.ID(profileID)); serr == nil {
			hint = state.Email
		} else {
			log.Debugf("failed to get profile state for login hint: %v", serr)
		}
	}
	if hint != "" {
		req.Hint = ptrStr(hint)
	}

	resp, err := cli.Login(ctx, req)
	if err != nil {
		return LoginResult{}, s.classifyDaemonError(err)
	}
	log.Infof("daemon login response received, needs SSO login: %v", resp.GetNeedsSSOLogin())
	return LoginResult{
		NeedsSSOLogin:           resp.GetNeedsSSOLogin(),
		UserCode:                resp.GetUserCode(),
		VerificationURI:         resp.GetVerificationURI(),
		VerificationURIComplete: resp.GetVerificationURIComplete(),
		ProfileID:               profileID,
	}, nil
}

func (s *Connection) Up(ctx context.Context, p UpParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	log.Infof("sending up request to daemon")
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

// WaitSSOLoginAndUp blocks until the SSO login completes and then brings the
// connection up, both from the Go side. Keeping the post-login Up here rather
// than as a frontend continuation is deliberate: during SSO the tray window is
// hidden and the webview is suspended (macOS App Nap / hidden-window timer
// throttling), so a frontend-driven Up would not run until the user woke the
// window (e.g. by hovering the tray icon). Doing it in Go connects the moment
// the daemon reports SSO success. Returns the authenticated user's email.
func (s *Connection) WaitSSOLoginAndUp(ctx context.Context, wait WaitSSOParams, up UpParams) (string, error) {
	email, err := s.waitSSOLogin(ctx, wait)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := s.Up(ctx, up); err != nil {
		return "", err
	}
	return email, nil
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

	return nil
}

// waitSSOLogin blocks until the daemon reports the SSO login result and returns
// the authenticated user's email. It is unexported because the frontend drives
// SSO through the exported WaitSSOLoginAndUp.
func (s *Connection) waitSSOLogin(ctx context.Context, p WaitSSOParams) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	log.Infof("waiting for SSO login to complete")
	resp, err := cli.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{
		UserCode: p.UserCode,
		Hostname: p.Hostname,
	})
	if err != nil {
		return "", s.classifyDaemonError(err)
	}
	log.Infof("SSO login completed, daemon reported success")

	// Persist the account email the same way the CLI does after its own
	// WaitSSOLogin: the daemon returns it but cannot store it, since it runs as
	// root and the per-profile state file is user-owned (see Profiles.List).
	// Without this the profile has no email, so Profiles.List shows no account
	// and later logins and session extends go out without a login_hint —
	// leaving the IdP to guess which account was meant.
	if email := resp.GetEmail(); email != "" {
		state := &profilemanager.ProfileState{Email: email}
		pm := profilemanager.NewProfileManager()

		// Against the profile the login was started for: SSO spans seconds of
		// user interaction, and a profile switch in that window would otherwise
		// file the email under the wrong profile.
		if p.ProfileID != "" {
			err = pm.SetProfileState(profilemanager.ID(p.ProfileID), state)
		} else {
			err = pm.SetActiveProfileState(state)
		}
		if err != nil {
			// Non-fatal: the login itself succeeded.
			log.Warnf("failed to store account email: %v", err)
		}
	}

	return resp.GetEmail(), nil
}

// classifyDaemonError maps a gRPC error to a localised ClientError.
func (s *Connection) classifyDaemonError(err error) *ClientError {
	return s.classifier.classify(err)
}
