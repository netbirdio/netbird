package profilemanager

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/getent"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// MigrateLegacyProfiles prepares the per-username layout for a daemon that
// addresses profiles by ID and owner.
//
// Two things have to be settled before a directory name can stop carrying
// meaning. Every profile needs an ID no other profile holds, since a legacy ID
// is a display name two accounts can each have, and the profiles of the account
// the machine last ran as need their owner recorded, which the active profile
// state is the only lossless record of.
//
// The profiles.v1 directory is the marker and is created only once both are
// done, so a run that fails leaves no marker and is retried on the next start.
// Callers log a failure and carry on rather than refusing to start.
func (s *ServiceManager) MigrateLegacyProfiles() error {
	dest := s.profilesDirPath()
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	profiles, err := s.loadAllProfiles()
	if err != nil {
		return fmt.Errorf("load profiles: %w", err)
	}

	active, err := s.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("active profile state: %w", err)
	}

	if err := s.rekeyDuplicateIDs(profiles, active); err != nil {
		return err
	}

	if err := s.stampActiveUserDir(profiles, active); err != nil {
		return err
	}

	if err := os.MkdirAll(dest, 0700); err != nil {
		return fmt.Errorf("create shared profile directory: %w", err)
	}

	log.Infof("profile migration complete, %s now marks it done", dest)
	return nil
}

// rekeyDuplicateIDs gives every profile sharing an ID a fresh one, in place.
// The file stays in its directory, only its name changes, so nothing that holds
// a path to a sibling file is disturbed.
func (s *ServiceManager) rekeyDuplicateIDs(profiles []Profile, active *ActiveProfileState) error {
	groups := make(map[ID][]*Profile, len(profiles))
	for i := range profiles {
		p := &profiles[i]
		if p.ID == defaultProfileName {
			continue
		}
		groups[p.ID] = append(groups[p.ID], p)
	}

	activeDir := sanitizeProfileName(active.Username)
	for id, group := range groups {
		if len(group) < 2 {
			continue
		}

		// Renaming the active profile without knowing which of the namesakes it
		// is would leave the active state pointing at nothing. The recorded
		// username is the only thing that tells them apart, so without it the
		// safer move is to leave the group alone and keep resolving it the old
		// way.
		if id == active.ID && activeDir == "" {
			log.Warnf("leaving %d profiles named %q as they are, the active profile state does not say which one is active", len(group), id)
			continue
		}

		for _, p := range group {
			wasActive := id == active.ID && filepath.Base(filepath.Dir(p.Path)) == activeDir

			fresh, err := generateProfileID()
			if err != nil {
				return fmt.Errorf("generate profile ID: %w", err)
			}
			if err := rekeyProfile(p, fresh); err != nil {
				return err
			}

			if wasActive {
				active.ID = fresh
				if err := s.SetActiveProfileState(active); err != nil {
					return fmt.Errorf("repoint active profile: %w", err)
				}
			}
		}
	}

	return nil
}

// rekeyProfile renames a profile and its sidecars to a fresh ID.
func rekeyProfile(p *Profile, fresh ID) error {
	// A legacy profile's display name is its filename, so it has to be in the
	// file before the filename stops meaning anything. The loader already
	// falls back to the stem, so writing p.Name is a no-op when the file
	// carries a name of its own.
	if err := writeProfileName(p.Path, p.Name); err != nil {
		return fmt.Errorf("record display name of %s: %w", p.ID, err)
	}

	dir := filepath.Dir(p.Path)
	target := filepath.Join(dir, fresh.String()+".json")
	if err := os.Rename(p.Path, target); err != nil {
		return fmt.Errorf("rekey %s: %w", p.ID, err)
	}

	for _, suffix := range []string{stateFileSuffix, prefsFileSuffix} {
		src := filepath.Join(dir, p.ID.String()+suffix)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, fresh.String()+suffix)); err != nil {
			log.Warnf("could not rename %s alongside its profile: %v", src, err)
		}
	}

	log.Infof("profile %q in %s now has the unique ID %s", p.ID, dir, fresh)
	p.ID, p.Path = fresh, target
	return nil
}

// stampActiveUserDir records the owner of every unowned profile in the
// directory of the account the active profile state names.
//
// That name is the one lossless input the old layout left behind. Resolving it
// forward, from name to uid, avoids reversing a sanitized directory name, which
// no amount of enumeration does reliably.
func (s *ServiceManager) stampActiveUserDir(profiles []Profile, active *ActiveProfileState) error {
	if active.Username == "" {
		return nil
	}

	u, err := getent.LookupUser(active.Username)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", active.Username, err)
	}

	principal, ok := principalForUser(u)
	if !ok {
		return fmt.Errorf("account %q has no usable id %q", active.Username, u.Uid)
	}

	dir := sanitizeProfileName(active.Username)
	for i := range profiles {
		p := &profiles[i]
		if len(p.Owners) > 0 || p.LegacyUserDir != dir {
			continue
		}
		if err := stampPrincipal(p.Path, principal); err != nil {
			return fmt.Errorf("stamp %s: %w", p.ID, err)
		}
		log.Infof("recorded %s as the owner of %s, the directory it sits in is that account's", principal, p.Path)
	}

	return nil
}

// principalForUser turns a resolved account into an owner principal. os/user
// reports a numeric id on Unix and a SID on Windows, which is what tells the
// two kinds apart without a build tag.
func principalForUser(u *user.User) (string, bool) {
	if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
		return ipcauth.UIDPrincipal(uint32(uid)), true
	}
	if strings.HasPrefix(u.Uid, "S-") {
		return ipcauth.SIDPrincipal(u.Uid), true
	}
	return "", false
}
