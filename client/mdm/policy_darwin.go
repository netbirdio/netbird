//go:build darwin && !ios

package mdm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"howett.net/plist"
)

// policyPlistPath is the well-known location where macOS writes the
// device-level mandatory MDM payload for NetBird. The path is fixed by
// Apple convention: when an MDM provider (Jamf / Kandji / Mosyle /
// Intune for Mac / Workspace ONE) pushes a Configuration Profile that
// contains a com.apple.ManagedClient.preferences payload targeting the
// bundle id io.netbird.client, the OS materializes the payload here.
//
// Read-only — only the OS (root) is supposed to write this file. The
// loader sanity-checks the file mode and refuses to honour a world-
// writable plist, as a defense against tampered installs.
const policyPlistPath = "/Library/Managed Preferences/io.netbird.client.plist"

// loadPlatformPolicy reads the MDM-managed configuration from the macOS
// managed-preferences plist at policyPlistPath. Returns:
//   - (nil, nil)  when the plist is absent (device not MDM-enrolled for
//     NetBird, or admin has not yet pushed a payload)
//   - (map, nil)  with N entries when N managed values are present
//     (N may be 0 — empty plist still signals enrollment to the caller)
//   - (nil, err)  on permission / parse / safety errors (including
//     refusal to read a world-writable plist)
//
// Top-level plist keys are canonicalised case-insensitively to the
// package's internal mdm.Key* names; unknown keys are logged and
// skipped so a stray entry in the payload does not block startup.
// Native plist value types map naturally onto the Policy accessor
// expectations (GetString / GetBool / GetInt / GetStringSlice).
func loadPlatformPolicy() (map[string]any, error) {
	f, err := os.Open(policyPlistPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Not enrolled for NetBird. Caller treats nil as
			// "no MDM source present".
			//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see LoadPolicy.
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", policyPlistPath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Warnf("MDM close plist %s: %v", policyPlistPath, closeErr)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", policyPlistPath, err)
	}
	// World-writable plist => tampered install. Refuse rather than
	// honour potentially attacker-controlled policy values.
	if info.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("refusing to read world-writable MDM source %s (mode %o)",
			policyPlistPath, info.Mode().Perm())
	}

	raw := make(map[string]any)
	if err := plist.NewDecoder(f).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode plist %s: %w", policyPlistPath, err)
	}

	out := make(map[string]any, len(raw))
	for name, val := range raw {
		// macOS / AppConfig conventions both use camelCase for managed
		// preferences keys; canonicalize to the mdm.Key* form so a key
		// written as "ManagementURL" (PascalCase, rare on macOS but
		// possible if the admin reused an ADMX-style name) still
		// resolves.
		canonical, known := canonicalKey[strings.ToLower(name)]
		if !known {
			log.Warnf("MDM ignoring unknown plist key %s: %s", policyPlistPath, name)
			continue
		}
		out[canonical] = val
	}
	return out, nil
}
