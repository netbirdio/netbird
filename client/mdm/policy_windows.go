//go:build windows

package mdm

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

// policyRegistryPath is the well-known MDM policy registry key for NetBird.
// Admins push values here through Group Policy, Intune ADMX ingestion, an
// Intune custom Registry CSP profile, or `reg add` during MSI deployment.
// Listed in the project's docs/mdm/netbird.admx schema.
const policyRegistryPath = `Software\Policies\NetBird`

// readRegistryValue reads a single value under policyRegistryPath and,
// on success, stores the type-coerced result in out[canonical]. Type
// coercion mirrors loadPlatformPolicy's documented mapping:
//   - REG_SZ / REG_EXPAND_SZ -> string (REG_EXPAND_SZ is expanded by the API)
//   - REG_DWORD / REG_QWORD  -> int64
//   - REG_MULTI_SZ           -> []string
//
// Unsupported value types and per-value read failures are logged at
// warn level and skipped — one malformed value must not block the
// surrounding loop. Extracted from loadPlatformPolicy to keep that
// function's cognitive complexity in check.
func readRegistryValue(k registry.Key, name, canonical string, out map[string]any) {
	_, valType, err := k.GetValue(name, nil)
	if err != nil {
		log.Warnf("MDM stat %s\\%s: %v", policyRegistryPath, name, err)
		return
	}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		if v, _, err := k.GetStringValue(name); err == nil {
			out[canonical] = v
		} else {
			log.Warnf("MDM read string %s\\%s: %v", policyRegistryPath, name, err)
		}
	case registry.DWORD, registry.QWORD:
		if v, _, err := k.GetIntegerValue(name); err == nil {
			// uint64 from the registry API; Policy.GetBool / GetInt
			// helpers consume int64, so narrow safely.
			out[canonical] = int64(v)
		} else {
			log.Warnf("MDM read int %s\\%s: %v", policyRegistryPath, name, err)
		}
	case registry.MULTI_SZ:
		if v, _, err := k.GetStringsValue(name); err == nil {
			out[canonical] = v
		} else {
			log.Warnf("MDM read multi-string %s\\%s: %v", policyRegistryPath, name, err)
		}
	default:
		log.Warnf("MDM ignoring unsupported registry value type %d at %s\\%s",
			valType, policyRegistryPath, name)
	}
}

// loadPlatformPolicy reads the MDM-managed configuration from the
// Windows registry under HKLM\Software\Policies\NetBird. Returns:
//   - (nil, nil)  when the key is absent (device not MDM-enrolled for NetBird)
//   - (map, nil)  with N entries when N managed values are set (N may be 0)
//   - (nil, err)  on open / enumerate registry errors
//
// Per-value type coercion + skip-on-error is delegated to
// readRegistryValue. Unknown value names are logged and skipped so a
// malformed deployment does not block startup.
func loadPlatformPolicy() (map[string]any, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// Not enrolled. Caller treats nil as "no MDM source present".
			//nolint:nilnil // (nil, nil) is the documented platform-absent sentinel; see LoadPolicy.
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", policyRegistryPath, err)
	}
	defer func() {
		if closeErr := k.Close(); closeErr != nil {
			log.Warnf("MDM close registry key %s: %v", policyRegistryPath, closeErr)
		}
	}()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate values of %s: %w", policyRegistryPath, err)
	}

	out := make(map[string]any, len(names))
	for _, name := range names {
		// Canonicalize the registry value name against the known MDM key
		// set so Policy.HasKey lookups (which use the canonical names)
		// succeed regardless of the casing used by the admin's ADMX or
		// `reg add` command.
		canonical, known := canonicalKey[strings.ToLower(name)]
		if !known {
			log.Warnf("MDM ignoring unknown registry value %s\\%s", policyRegistryPath, name)
			continue
		}
		readRegistryValue(k, name, canonical, out)
	}
	return out, nil
}
