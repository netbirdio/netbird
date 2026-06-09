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

// loadPlatformPolicy reads the MDM-managed configuration from the Windows
// registry under HKLM\Software\Policies\NetBird. Returns:
//   - (nil, nil)  when the key is absent (device not MDM-enrolled for NetBird)
//   - (map, nil)  with N entries when N managed values are set (N may be 0)
//   - (nil, err)  on any other registry error
//
// Type coercion of registry value types into the Policy map:
//   - REG_SZ        -> string
//   - REG_EXPAND_SZ -> string (expanded by the registry API)
//   - REG_DWORD     -> int64 (caller's GetBool handles 0/!=0 coercion)
//   - REG_QWORD     -> int64
//   - REG_MULTI_SZ  -> []string
//
// Unsupported value types (REG_BINARY, REG_NONE, ...) are skipped with a
// loadPlatformPolicy reads managed NetBird policy values from HKLM\Software\Policies\NetBird.
// If the registry key does not exist it returns (nil, nil).
// It returns a map whose keys are canonical policy names and whose values are coerced from registry types:
// REG_SZ/REG_EXPAND_SZ -> string, REG_DWORD/REG_QWORD -> int64, REG_MULTI_SZ -> []string.
// readRegistryValue reads the registry value named by name from key k and, when the value is successfully read and its type is supported, stores the coerced Go value in out[canonical].
//
// REG_SZ and REG_EXPAND_SZ are stored as string, REG_DWORD and REG_QWORD are stored as int64, and REG_MULTI_SZ is stored as []string; unknown value names, unsupported value types, and per-value read errors are logged and skipped.
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

// loadPlatformPolicy loads MDM-managed NetBird policy values from the Windows
// registry at HKLM\Software\Policies\NetBird.
// 
// It returns a map that maps canonical policy names to coerced Go values:
// string for REG_SZ/REG_EXPAND_SZ, int64 for REG_DWORD/REG_QWORD, and []string
// for REG_MULTI_SZ. If the policy registry key does not exist, it returns
// (nil, nil). It returns an error when opening or enumerating the registry
// key fails. Individual values that are unknown, of unsupported types, or that
// fail to read are skipped and produce logged warnings; registry close failures
// are also logged.
func loadPlatformPolicy() (map[string]any, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// Not enrolled. Caller treats nil as "no MDM source present".
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
