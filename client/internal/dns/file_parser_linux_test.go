//go:build !android

package dns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseResolvConf(t *testing.T) {
	testCases := []struct {
		input          string
		expectedSearch []string
		expectedNS     []string
		expectedOther  []string
	}{
		{
			input: `domain example.org
search example.org
nameserver 192.168.0.1
`,
			expectedSearch: []string{"example.org"},
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
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			tmpResolvConf := filepath.Join(t.TempDir(), "resolv.conf")
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

func Test_emptyFile(t *testing.T) {
	cfg, err := parseResolvConfFile("/tmp/nothing")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if len(cfg.others) != 0 || len(cfg.searchDomains) != 0 || len(cfg.nameServers) != 0 {
		t.Errorf("expected empty config, got %v", cfg)
	}
}

func Test_symlink(t *testing.T) {
	input := `# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
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

nameserver 192.168.0.1
`

	tmpResolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	err := os.WriteFile(tmpResolvConf, []byte(input), 0644)
	if err != nil {
		t.Fatal(err)
	}

	tmpLink := filepath.Join(t.TempDir(), "symlink")
	err = os.Symlink(tmpResolvConf, tmpLink)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := parseResolvConfFile(tmpLink)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.nameServers) != 1 {
		t.Errorf("unexpected resolv.conf content: %v", cfg)
	}
}

func TestPrepareOptionsWithTimeout(t *testing.T) {
	tests := []struct {
		name     string
		others   []string
		timeout  int
		attempts int
		expected []string
	}{
		{
			name:     "Append new options with timeout and attempts",
			others:   []string{"some config"},
			timeout:  2,
			attempts: 2,
			expected: []string{"some config", "options timeout:2 attempts:2"},
		},
		{
			name:     "Modify existing options to exclude rotate and include timeout and attempts",
			others:   []string{"some config", "options rotate someother"},
			timeout:  3,
			attempts: 2,
			expected: []string{"some config", "options attempts:2 timeout:3 someother"},
		},
		{
			name:     "Existing options with timeout and attempts are updated",
			others:   []string{"some config", "options timeout:4 attempts:3"},
			timeout:  5,
			attempts: 4,
			expected: []string{"some config", "options timeout:5 attempts:4"},
		},
		{
			name:     "Modify existing options, add missing attempts before timeout",
			others:   []string{"some config", "options timeout:4"},
			timeout:  4,
			attempts: 3,
			expected: []string{"some config", "options attempts:3 timeout:4"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := prepareOptionsWithTimeout(tc.others, tc.timeout, tc.attempts)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestRemoveFirstNbNameserver(t *testing.T) {
	testCases := []struct {
		name       string
		content    string
		ipToRemove string
		expected   string
	}{
		{
			name: "Unrelated nameservers with comments and options",
			content: `# This is a comment
options rotate
nameserver 1.1.1.1
# Another comment
nameserver 8.8.4.4
search example.com`,
			ipToRemove: "9.9.9.9",
			expected: `# This is a comment
options rotate
nameserver 1.1.1.1
# Another comment
nameserver 8.8.4.4
search example.com`,
		},
		{
			name: "First nameserver matches",
			content: `search example.com
nameserver 9.9.9.9
# oof, a comment
nameserver 8.8.4.4
options attempts:5`,
			ipToRemove: "9.9.9.9",
			expected: `search example.com
# oof, a comment
nameserver 8.8.4.4
options attempts:5`,
		},
		{
			name: "Target IP not the first nameserver",
			// nolint:dupword
			content: `# Comment about the first nameserver
nameserver 8.8.4.4
# Comment before our target
nameserver 9.9.9.9
options timeout:2`,
			ipToRemove: "9.9.9.9",
			// nolint:dupword
			expected: `# Comment about the first nameserver
nameserver 8.8.4.4
# Comment before our target
nameserver 9.9.9.9
options timeout:2`,
		},
		{
			name: "Only nameserver matches",
			content: `options debug
nameserver 9.9.9.9
search localdomain`,
			ipToRemove: "9.9.9.9",
			expected: `options debug
nameserver 9.9.9.9
search localdomain`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			tempFile := filepath.Join(tempDir, "resolv.conf")
			err := os.WriteFile(tempFile, []byte(tc.content), 0644)
			assert.NoError(t, err)

			err = removeFirstNbNameserver(tempFile, tc.ipToRemove)
			assert.NoError(t, err)

			content, err := os.ReadFile(tempFile)
			assert.NoError(t, err)

			assert.Equal(t, tc.expected, string(content), "The resulting content should match the expected output.")
		})
	}
}
