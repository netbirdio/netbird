//go:build !android

package dns

import (
	"fmt"
	"os"
	"testing"
)

func Test_parseResolvConf(t *testing.T) {
	testCases := []struct {
		input          string
		expectedSearch []string
		expectedNS     []string
		expectedOther  []string
	}{
		{
			input: `domain chello.hu
search chello.hu
nameserver 192.168.0.1
`,
			expectedSearch: []string{"chello.hu"},
			expectedNS:     []string{"192.168.0.1"},
			expectedOther:  []string{},
		},
		{
			input: `# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# This file might be symlinked as /etc/resolv.conf. If you're looking at
# /etc/resolv.conf and seeing this text, you have followed the symlink.
#
# This is a dynamic resolv.conf file for connecting local clients directly to
# all known uplink DNS servers. This file lists all configured search domains.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a
# different way, replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 192.168.2.1
nameserver 100.81.99.197
search netbird.cloud
`,
			expectedSearch: []string{"netbird.cloud"},
			expectedNS:     []string{"192.168.2.1", "100.81.99.197"},
			expectedOther:  []string{},
		},
		{
			input: `# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# This file might be symlinked as /etc/resolv.conf. If you're looking at
# /etc/resolv.conf and seeing this text, you have followed the symlink.
#
# This is a dynamic resolv.conf file for connecting local clients directly to
# all known uplink DNS servers. This file lists all configured search domains.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a
# different way, replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 192.168.2.1
nameserver 100.81.99.197
search netbird.cloud
options debug
`,
			expectedSearch: []string{"netbird.cloud"},
			expectedNS:     []string{"192.168.2.1", "100.81.99.197"},
			expectedOther:  []string{"options debug"},
		},
		{
			input: `# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# This file might be symlinked as /etc/resolv.conf. If you're looking at
# /etc/resolv.conf and seeing this text, you have followed the symlink.
#
# This is a dynamic resolv.conf file for connecting local clients directly to
# all known uplink DNS servers. This file lists all configured search domains.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a
# different way, replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 192.168.2.1
nameserver 100.81.99.197
search netbird.cloud
options debug
options edns0 trust-ad
`,
			expectedSearch: []string{"netbird.cloud"},
			expectedNS:     []string{"192.168.2.1", "100.81.99.197"},
			expectedOther:  []string{"options debug", "options edns0 trust-ad"},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			tmpResolvConf := fmt.Sprintf("%s/%s", t.TempDir(), "resolv.conf")
			err := os.WriteFile(tmpResolvConf, []byte(testCase.input), 0644)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := parseResolvConfFile(tmpResolvConf)
			if err != nil {
				t.Fatal(err)
			}
			ok := compareLists(cfg.searchDomains, testCase.expectedSearch)
			if !ok {
				t.Errorf("invalid parse result for search domains, expected: %v, got: %v", testCase.expectedSearch, cfg.searchDomains)
			}

			ok = compareLists(cfg.nameServers, testCase.expectedNS)
			if !ok {
				t.Errorf("invalid parse result for ns domains, expected: %v, got: %v", testCase.expectedNS, cfg.nameServers)
			}

			ok = compareLists(cfg.others, testCase.expectedOther)
			if !ok {
				t.Errorf("invalid parse result for others, expected: %v, got: %v", testCase.expectedOther, cfg.others)
			}
		})
	}

}

func compareLists(search []string, search2 []string) bool {
	if len(search) != len(search2) {
		return false
	}
	for i, v := range search {
		if v != search2[i] {
			return false
		}
	}
	return true
}
