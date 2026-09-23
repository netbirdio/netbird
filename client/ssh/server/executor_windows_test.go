//go:build windows

package server

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// A computer name longer than MAX_COMPUTERNAME_LENGTH makes the DNS host name
// and the NetBIOS name differ, and Windows qualifies local accounts with the
// NetBIOS one. Comparing against the DNS host name, as this code did before,
// classified every local account on such a machine as a domain account and sent
// it down the Kerberos S4U path in search of a domain controller.
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
		// A machine that cannot name itself must not resolve to local: that
		// would authenticate a same named local account in place of the
		// domain one.
		{"unreadable_machine_name", netbios, unreadable, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLocalDomain(tt.domain, tt.machineName),
				"classification of domain %q", tt.domain)
		})
	}
}

// The built-in Administrator (RID 500) exists on every Windows installation and
// is always a local account, so Windows qualifies it with this machine's
// NetBIOS name. This checks end to end that the name Windows puts on a local
// account is the name isLocalUser compares against. The test process itself is
// not usable here: CI runs the suite as SYSTEM, whose qualified name carries
// the NT AUTHORITY prefix rather than a machine name.
func TestIsLocalUser_LocalAccount(t *testing.T) {
	netbios, err := netbiosComputerName()
	require.NoError(t, err, "read NetBIOS computer name")
	require.NotEmpty(t, netbios, "NetBIOS computer name must not be empty")
	assert.LessOrEqual(t, len(netbios), windows.MAX_COMPUTERNAME_LENGTH,
		"NetBIOS computer name is capped at MAX_COMPUTERNAME_LENGTH")

	account, err := user.Lookup(localAccountNameByRID(t, 500))
	require.NoError(t, err, "look up the built-in Administrator account")

	_, domain := parseUsername(account.Username)
	assert.True(t, strings.EqualFold(netbios, domain),
		"Windows must qualify local account %q with NetBIOS name %q", account.Username, netbios)
	assert.True(t, NewPrivilegeDropper().isLocalUser(domain),
		"account %q must be classified as local", account.Username)
}
