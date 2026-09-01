package mobile

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

const (
	// profileAccountSuffix names the file holding the profile's account email.
	// Deliberately not ".state.json", which desktop uses for the same data:
	// there the email and the engine's state manager live in different
	// directories, but on mobile both resolve under configDir, so sharing the
	// name would have the two overwrite each other — the state manager rewrites
	// the whole file from its own keys (see statemanager.Manager.PersistState),
	// and this package's writer does the same in reverse.
	profileAccountSuffix = ".account.json"
)

// profileAccountPathFor derives the account file path from a profile's config
// path: netbird.cfg -> netbird.account.json, <id>.json -> <id>.account.json.
//
// Deriving from the config path rather than resolving the active profile keeps
// the write on the profile the login actually ran for: login flows run in a
// goroutine, so the active profile can change under a flow already in flight.
func profileAccountPathFor(configPath string) (string, error) {
	if configPath == "" {
		return "", fmt.Errorf("empty config path")
	}

	base := filepath.Base(configPath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" || stem == "." {
		return "", fmt.Errorf("config path %q has no filename stem", configPath)
	}

	return filepath.Join(filepath.Dir(configPath), stem+profileAccountSuffix), nil
}

// ReadProfileEmail returns the account email stored for the profile whose
// config lives at configPath. A missing or unreadable file yields "", which
// leaves the account choice to the IdP.
func ReadProfileEmail(configPath string) string {
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

// WriteProfileEmail records the account email for the profile whose config
// lives at configPath, so later logins can pass it as an OIDC login_hint. An
// empty email is ignored rather than blanking what is already stored.
func WriteProfileEmail(configPath string, email string) error {
	if email == "" {
		return nil
	}

	accountPath, err := profileAccountPathFor(configPath)
	if err != nil {
		return fmt.Errorf("resolve profile account path: %w", err)
	}

	// DirectWriteJson, not the atomic writers: those create a temp file and
	// rename it over the target, which the tvOS App Group sandbox blocks. It is
	// the same reason the config next to this file goes through
	// DirectWriteOutConfig. The file is rewritten whole from one key, so losing
	// atomicity costs nothing beyond a torn write on a crash mid-write, which
	// reads back as "no email" and is recovered by the next login.
	state := profilemanager.ProfileState{Email: email}
	if err := util.DirectWriteJson(context.Background(), accountPath, state); err != nil {
		return fmt.Errorf("write profile account: %w", err)
	}

	return nil
}

// removeProfileEmail drops the stored account email. Called on profile removal,
// not on logout: a logged-out profile keeps its email so the next login passes
// it as the login_hint, matching the desktop and CLI semantics. Mirrors the
// desktop UI's RemoveProfileState call.
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
