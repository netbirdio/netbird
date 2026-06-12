//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// ErrorTranslator localises daemon errors; runtime impl is *i18n.Bundle.
type ErrorTranslator interface {
	Translate(lang i18n.LanguageCode, key string, args ...string) string
}

// LanguagePreference reports the current UI language; runtime impl is *preferences.Store.
type LanguagePreference interface {
	Get() preferences.UIPreferences
}

// ClientError is a structured error returned to the frontend. The frontend
// translates Code via i18n; Short is an English fallback; Long carries the
// unwrapped daemon message.
type ClientError struct {
	Code  string `json:"code"`
	Short string `json:"short"`
	Long  string `json:"long"`
}

// Error returns the short message for plain Go callers.
func (e *ClientError) Error() string {
	if e == nil {
		return ""
	}
	return e.Short
}

// MarshalJSON emits the struct so the Wails binding sends an object, not the
// default "error: ..." string.
func (e *ClientError) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}
	type alias ClientError
	return json.Marshal((*alias)(e))
}

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
	translator ErrorTranslator
	prefs      LanguagePreference
}

// NewConnection wires up a Connection. translator or prefs may be nil, in which
// case classifyDaemonError falls back to the bare error key.
func NewConnection(conn DaemonConn, translator ErrorTranslator, prefs LanguagePreference) *Connection {
	return &Connection{conn: conn, translator: translator, prefs: prefs}
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

// classifyDaemonError maps a gRPC error to a ClientError by matching known
// substrings to a stable code. A missing locale entry surfaces as a visible
// "error.<code>" string — a deliberate fail-loud signal to update the bundle.
func (s *Connection) classifyDaemonError(err error) *ClientError {
	if err == nil {
		return nil
	}

	msg := err.Error()
	if st, ok := gstatus.FromError(err); ok {
		msg = st.Message()
	}
	lower := strings.ToLower(msg)

	code := "unknown"
	switch {
	case strings.Contains(lower, "token used before issued"),
		strings.Contains(lower, "token is not valid yet"):
		code = "jwt_clock_skew"
	case strings.Contains(lower, "token is expired"),
		strings.Contains(lower, "token has expired"):
		code = "jwt_expired"
	case strings.Contains(lower, "token signature is invalid"):
		code = "jwt_signature_invalid"
	case strings.Contains(lower, "peer login has expired"):
		code = "session_expired"
	case strings.Contains(lower, "invalid setup-key"),
		strings.Contains(lower, "invalid setup key"):
		code = "invalid_setup_key"
	case strings.Contains(lower, "permission denied"):
		code = "permission_denied"
	case strings.Contains(lower, "no connection could be made"),
		strings.Contains(lower, "connection refused"),
		strings.Contains(lower, "context deadline exceeded"):
		code = "daemon_unreachable"
	}

	return &ClientError{
		Code:  code,
		Short: s.translateShort(code),
		Long:  msg,
	}
}

// translateShort resolves the localised short message for code, returning the
// bare "error.<code>" key when no translation is available so the gap stays visible.
func (s *Connection) translateShort(code string) string {
	key := "error." + code
	if s.translator == nil {
		return key
	}
	lang := i18n.DefaultLanguage
	if s.prefs != nil {
		if pref := s.prefs.Get().Language; pref != "" {
			lang = pref
		}
	}
	return s.translator.Translate(lang, key)
}
