//go:build (linux && !android) || windows || (darwin && !ios)

package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCleanHardwareUUID(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		// Linux sysfs is lowercase with a trailing newline, Windows WMI and macOS
		// IOPlatformUUID are uppercase: the case must survive so it matches osquery.
		{name: "linux sysfs", raw: "4c4c4544-0042-3510-8051-b4c04f4e3332\n", want: "4c4c4544-0042-3510-8051-b4c04f4e3332"},
		{name: "uppercase kept", raw: "4C4C4544-0042-3510-8051-B4C04F4E3332", want: "4C4C4544-0042-3510-8051-B4C04F4E3332"},
		{name: "empty", raw: "", want: ""},
		{name: "whitespace only", raw: " \n", want: ""},
		{name: "all zero", raw: "00000000-0000-0000-0000-000000000000", want: ""},
		{name: "all F uppercase", raw: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", want: ""},
		{name: "OEM sequence", raw: "03000200-0400-0500-0006-000700080009", want: ""},
		{name: "OEM sequence uppercase", raw: "03020100-0504-0706-0809-0A0B0C0D0E0F\n", want: ""},
		{name: "OEM default", raw: "10000000-0000-8000-0040-000000000000", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, cleanHardwareUUID(tt.raw), "cleaned hardware UUID")
		})
	}
}
