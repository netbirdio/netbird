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

	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// ErrorTranslator is the subset of i18n.Bundle Connection needs to localise
// daemon errors. Defined as an interface so tests can stub it; the runtime
// implementation is *i18n.Bundle.
type ErrorTranslator interface {
	Translate(lang i18n.LanguageCode, key string, args ...string) string
}

// LanguagePreference is the subset of preferences.Store Connection needs
// to discover the current UI language at error-classification time. The
// runtime implementation is *preferences.Store.
type LanguagePreference interface {
	Get() preferences.UIPreferences
}

// ClientError is a structured error returned to the frontend.
//
// The daemon hands us gRPC errors whose Message is a stack of wrapped strings
// from the management server and the underlying JWT library, for example:
//
//	"invalid jwt token, err: token could not be parsed: token has invalid
//	 claims: token used before issued"
//
// Showing that raw message in a native dialog is unreadable, so we map the
// substrings we recognise to a {code, short, long} triple. The frontend
// translates Code through i18n (preferred); Short is an English fallback so
// the dialog still reads cleanly if a code is missing from the locale; Long
// always carries the unwrapped daemon message for the operator.
type ClientError struct {
	Code  string `json:"code"`
	Short string `json:"short"`
	Long  string `json:"long"`
}

// Error returns the user-facing short message so plain Go callers and the
// Wails default error path still get a readable string.
func (e *ClientError) Error() string {
	if e == nil {
		return ""
	}
	return e.Short
}

// MarshalJSON encodes the full {code, short, long} triple so the Wails
// binding emits a structured object instead of the default "error: ..."
// string. The TS layer accesses these fields via try/catch.
func (e *ClientError) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}
	type alias ClientError
	return json.Marshal((*alias)(e))
}

// classifyDaemonError turns a raw gRPC error from the daemon into a
// ClientError with a stable code and a short localised summary. The Long
// field always carries the unwrapped daemon message so the operator can
// inspect the root cause when the short text is too generic. Short is
// looked up via i18n under "error.<code>": i18n.Bundle.Translate already
// handles current-language → English → key passthrough, so any missing
// locale entry surfaces as a visible "error.<code>" string in the dialog —
// a deliberate fail-loud signal that the bundle needs updating.
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

// translateShort resolves the localised short message for code. The i18n
// Bundle's own Translate already falls back current-language → English →
// key passthrough, so callers either see the localised string or the bare
// "error.<code>" key (which makes the missing translation obvious). If
// the translator is nil — e.g. a Connection constructed in a unit test —
// we return the key for the same reason.
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
	conn       DaemonConn
	translator ErrorTranslator
	prefs      LanguagePreference
}

// NewConnection wires Connection with its translation dependencies. Either
// translator or prefs may be nil; in that case classifyDaemonError falls
// back to the English Short text baked into the error map. main.go always
// supplies both at startup.
func NewConnection(conn DaemonConn, translator ErrorTranslator, prefs LanguagePreference) *Connection {
	return &Connection{conn: conn, translator: translator, prefs: prefs}
}

func (s *Connection) Login(ctx context.Context, p LoginParams) (LoginResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return LoginResult{}, err
	}

	// No pre-Login Down: the daemon's Login dislodges a pending WaitSSOLogin
	// itself (server.go cancels the in-flight wait via actCancel), and an
	// abandoned browser leg is torn down by startLogin cancelling the
	// WaitSSOLogin RPC, which the daemon reacts to by clearing the stale
	// OAuth flow. A defensive Down here would only add a visible Idle blink
	// to the tray during the SSO handoff (Connect/profile-switch →
	// NeedsLogin → auto-login) for no gain.

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
	// The UI always uses async mode: status updates flow via SubscribeStatus.
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
