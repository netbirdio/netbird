//go:build windows

package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// Past 15 characters the DNS host name and the NetBIOS name differ, and Windows
// qualifies local accounts with the NetBIOS one.
func TestIsLocalDomain(t *testing.T) {
	const dnsHostname = "WINTESTMACHINE01XYZ" // 19 characters
	netbios := dnsHostname[:windows.MAX_COMPUTERNAME_LENGTH]
	require.NotEqual(t, strings.ToLower(dnsHostname), strings.ToLower(netbios),
		"a 19 character name must not equal its 15 character truncation")

	name := func() (string, error) { return netbios, nil }
	unreadable := func() (string, error) { return "", errors.New("name unavailable") }

	tests := []struct {
		name        string
		domain      string
		machineName func() (string, error)
		want        bool
	}{
		{"empty_domain", "", unreadable, true},
		{"dot_domain", ".", unreadable, true},
		{"truncated_netbios_name", netbios, name, true},
		{"netbios_name_lowercase", strings.ToLower(netbios), name, true},
		{"untruncated_dns_host_name", dnsHostname, name, false},
		{"real_domain", "CORP", name, false},
		// Must not resolve to local: that could authenticate the wrong account.
		{"unreadable_machine_name", netbios, unreadable, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLocalDomain(tt.domain, tt.machineName),
				"classification of domain %q", tt.domain)
		})
	}
}
