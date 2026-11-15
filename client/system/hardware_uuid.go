//go:build (linux && !android) || windows || (darwin && !ios)

package system

import "strings"

// placeholderHardwareUUIDs are firmware defaults shared by many machines. The first four
// mirror osquery's list, for which osquery reports a random UUID instead.
var placeholderHardwareUUIDs = map[string]struct{}{
	"00000000-0000-0000-0000-000000000000": {},
	"03000200-0400-0500-0006-000700080009": {},
	"03020100-0504-0706-0809-0a0b0c0d0e0f": {},
	"10000000-0000-8000-0040-000000000000": {},
	"ffffffff-ffff-ffff-ffff-ffffffffffff": {},
}

// cleanHardwareUUID keeps the case of raw untouched so the value matches osquery's
// system_info.uuid byte for byte. A placeholder is reported as empty because it does
// not identify the machine.
func cleanHardwareUUID(raw string) string {
	id := strings.TrimSpace(raw)
	if _, ok := placeholderHardwareUUIDs[strings.ToLower(id)]; ok {
		return ""
	}
	return id
}
