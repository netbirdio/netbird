//go:build ios

package NetBirdSDK

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util"
)

// profileAccountSuffix names the file holding the profile's account email.
// Deliberately not ".state.json": on iOS the profile directory already holds the
// engine's state.json, and the state manager rewrites that file from its own
// keys, so the two would overwrite each other.
const profileAccountSuffix = ".account.json"

// profileAccountPathFor derives the account file path from a profile's config
// path: profiles/<name>/netbird.cfg -> profiles/<name>/netbird.account.json.
//
// Deriving it from the config path rather than resolving the active profile
// keeps the write on the profile the login actually ran for: Auth.login runs in
// a goroutine, so the active profile can change under a flow already in flight.
func profileAccountPathFor(configPath string) (string, error) {
	if configPath == "" {
		return "", fmt.Errorf("empty config path")
	}

	base := filepath.Base(configPath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" || stem == "." || stem == ".." {
		return "", fmt.Errorf("config path %q has no filename stem", configPath)
	}

	return filepath.Join(filepath.Dir(configPath), stem+profileAccountSuffix), nil
}

// readProfileEmail returns the account email stored for the profile whose config
// lives at configPath. A missing or unreadable file yields "", which leaves the
// account choice to the IdP.
func readProfileEmail(configPath string) string {
	accountPath, err := profileAccountPathFor(configPath)
	if err != nil {
		log.Debugf("no profile account path for login hint: %v", err)
		return ""
	}

	var state profilemanager.ProfileState
	if _, err := util.ReadJson(accountPath, &state); err != nil {
		if !os.IsNotExist(err) {
			log.Debugf("failed to read profile account for login hint: %v", err)
		}
		return ""
	}

	return state.Email
}

// writeProfileEmail records the account email for the profile whose config lives
// at configPath, so later logins can pass it as an OIDC login_hint. An empty
// email is ignored rather than blanking what is already stored.
//
// The write is non-atomic on purpose: the tvOS App Group sandbox blocks the
// temp-file+rename the atomic helpers use, the same reason the config itself
// goes through DirectWriteOutConfig.
func writeProfileEmail(configPath string, email string) error {
	if email == "" {
		return nil
	}

	accountPath, err := profileAccountPathFor(configPath)
	if err != nil {
		return fmt.Errorf("resolve profile account path: %w", err)
	}

	state := profilemanager.ProfileState{Email: email}
	if err := util.DirectWriteJson(context.Background(), accountPath, state); err != nil {
		return fmt.Errorf("write profile account: %w", err)
	}

	return nil
}

// removeProfileEmail drops the stored account email. Called on logout: while the
// email is on disk it goes out as a login_hint, which would steer the next login
// straight back into the account just logged out of.
func removeProfileEmail(configPath string) error {
	accountPath, err := profileAccountPathFor(configPath)
	if err != nil {
		return fmt.Errorf("resolve profile account path: %w", err)
	}

	if err := os.Remove(accountPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove profile account: %w", err)
	}

	return nil
}

// ProfileAccountEmail returns the account email recorded for the profile whose
// config lives at configPath, or "" if that profile never completed an SSO login
// or was logged out. Display-only on the caller's side, so an unresolvable path
// degrades to "" rather than an error.
//
// Exported for the iOS/tvOS host app, which owns the profile directory layout
// and shows the account each profile belongs to.
func ProfileAccountEmail(configPath string) string {
	return readProfileEmail(configPath)
}

// ClearProfileAccountEmail removes the stored account email for the profile whose
// config lives at configPath. The host app calls it when logging a profile out,
// so the next login no longer carries a hint back into the account just left.
// Removing an email that was never stored succeeds.
func ClearProfileAccountEmail(configPath string) error {
	return removeProfileEmail(configPath)
}
