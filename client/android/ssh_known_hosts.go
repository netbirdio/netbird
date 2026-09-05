//go:build android

package android

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const knownHostsNamespace = "ssh"

const (
	hostKeyUnknown hostKeyVerdict = iota
	hostKeyMatched
	hostKeyChanged
)

var knownHostsMu sync.Mutex

type hostKeyVerdict uint8

type knownHostsSection struct {
	KnownHosts []string `json:"knownHosts"`
}

type knownHostsStore struct {
	prefs prefsStore
}

// RemoveKnownHost deletes every known-hosts entry for host:port from the
// profile's store, so a host trusted for a session that is being deleted does
// not linger. Java calls this only once no session targets that host, so a
// shared host stays trusted. A missing entry is not an error: the goal state
// is "absent".
func RemoveKnownHost(configDir, profileID, host string, port int) error {
	store, err := openKnownHostsStore(configDir, profileID)
	if err != nil {
		return err
	}
	return store.removeHost(host, port)
}

func openKnownHostsStore(configDir, profileID string) (*knownHostsStore, error) {
	prefs, err := newProfilePrefs(configDir, profileID)
	if err != nil {
		return nil, err
	}
	return &knownHostsStore{prefs: prefs}, nil
}

func (st *knownHostsStore) verify(hostname string, remote net.Addr, key gossh.PublicKey) (hostKeyVerdict, error) {
	lines, err := st.lines()
	if err != nil {
		return hostKeyUnknown, err
	}
	targets := knownHostsTargets(hostname, remote)

	verdict := hostKeyUnknown
	for _, line := range lines {
		pubKey, ok := knownHostsLineKey(line, targets)
		if !ok {
			continue
		}
		if pubKey.Type() == key.Type() && bytes.Equal(pubKey.Marshal(), key.Marshal()) {
			return hostKeyMatched, nil
		}
		verdict = hostKeyChanged
	}
	return verdict, nil
}

func (st *knownHostsStore) append(hostname string, remote net.Addr, key gossh.PublicKey) error {
	line := knownhosts.Line(knownHostsTargets(hostname, remote), key)

	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	lines, err := st.lines()
	if err != nil {
		return err
	}
	return st.prefs.Put(knownHostsNamespace, knownHostsSection{KnownHosts: append(lines, line)})
}

func (st *knownHostsStore) removeHost(host string, port int) error {
	target := knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))

	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	lines, err := st.lines()
	if err != nil {
		return err
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if knownHostsLineMatches(line, target) {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == len(lines) {
		return nil
	}
	return st.prefs.Put(knownHostsNamespace, knownHostsSection{KnownHosts: kept})
}

func (st *knownHostsStore) lines() ([]string, error) {
	var section knownHostsSection
	if _, err := st.prefs.Get(knownHostsNamespace, &section); err != nil {
		return nil, err
	}
	return section.KnownHosts, nil
}

func knownHostsTargets(hostname string, remote net.Addr) []string {
	targets := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if normalized := knownhosts.Normalize(remote.String()); normalized != targets[0] {
			targets = append(targets, normalized)
		}
	}
	return targets
}

func knownHostsLineKey(line string, targets []string) (gossh.PublicKey, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, false
	}
	_, hosts, pubKey, _, _, err := gossh.ParseKnownHosts([]byte(trimmed))
	if err != nil {
		return nil, false
	}
	for _, host := range hosts {
		for _, target := range targets {
			if host == target {
				return pubKey, true
			}
		}
	}
	return nil, false
}

// knownHostsLineMatches reports whether a known-hosts line's address list
// contains the normalized target. Comment and blank lines never match.
func knownHostsLineMatches(line, target string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return false
	}
	for _, addr := range strings.Split(fields[0], ",") {
		if addr == target {
			return true
		}
	}
	return false
}
