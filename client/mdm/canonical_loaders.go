//go:build windows || darwin

package mdm

import "strings"

// canonicalKey maps the lowercase form of a managed-config value name to
// its canonical mdm.Key* form. Admins commonly write PascalCase value
// names in ADMX / Group Policy ("ManagementURL"); the iOS/AppConfig and
// macOS plist conventions are camelCase ("managementURL"); both must
// resolve to the same Policy lookup.
//
// Lives in a desktop-loader-only file (build tag `windows || darwin`)
// because no other build path consumes it. Linux / FreeBSD / mobile
// builds don't ship a platform loader that reads arbitrary-case key
// names, so they don't need the canonicalisation table — and including
// the var unconditionally would trigger the `unused` golangci-lint
// check on those platforms.
var canonicalKey = func() map[string]string {
	m := make(map[string]string, len(AllKeys))
	for _, k := range AllKeys {
		m[strings.ToLower(k)] = k
	}
	return m
}()
