//go:build (linux && !android) || freebsd

package dns

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	netbirdManager osManagerType = iota
	fileManager
	networkManager
	systemdManager
	resolvConfManager
)

type osManagerType int

func (t osManagerType) String() string {
	switch t {
	case netbirdManager:
		return "netbird"
	case fileManager:
		return "file"
	case networkManager:
		return "networkManager"
	case systemdManager:
		return "systemd"
	case resolvConfManager:
		return "resolvconf"
	default:
		return "unknown"
	}
}

type restoreHostManager interface {
	hostManager
	restoreUncleanShutdownDNS(netip.Addr) error
}

func newHostManager(wgInterface string) (hostManager, error) {
	osManager, reason, err := getOSDNSManagerType()
	if err != nil {
		return nil, fmt.Errorf("get os dns manager type: %w", err)
	}

	log.Infof("System DNS manager discovered: %s (%s)", osManager, reason)
	mgr, err := newHostManagerFromType(wgInterface, osManager)
	// need to explicitly return nil mgr on error to avoid returning a non-nil interface containing a nil value
	if err != nil {
		return nil, fmt.Errorf("create host manager: %w", err)
	}

	return mgr, nil
}

func newHostManagerFromType(wgInterface string, osManager osManagerType) (restoreHostManager, error) {
	switch osManager {
	case networkManager:
		return newNetworkManagerDbusConfigurator(wgInterface)
	case systemdManager:
		return newSystemdDbusConfigurator(wgInterface)
	case resolvConfManager:
		return newResolvConfConfigurator(wgInterface)
	default:
		return newFileConfigurator()
	}
}

func getOSDNSManagerType() (osManagerType, string, error) {
	resolved := isSystemdResolvedRunning()
	nss := isLibnssResolveUsed()
	stub := checkStub()

	// Prefer systemd-resolved whenever it owns libc resolution, regardless of
	// who wrote /etc/resolv.conf. File-mode rewrites do not affect lookups
	// that go through nss-resolve, and in foreign mode they can loop back
	// through resolved as an upstream.
	if resolved && (nss || stub) {
		return systemdManager, fmt.Sprintf("systemd-resolved active (nss-resolve=%t, stub=%t)", nss, stub), nil
	}

	mgr, reason, rejected, err := scanResolvConfHeader()
	if err != nil {
		return 0, "", err
	}
	if reason != "" {
		return mgr, reason, nil
	}

	fallback := fmt.Sprintf("no manager matched (resolved=%t, nss-resolve=%t, stub=%t)", resolved, nss, stub)
	if len(rejected) > 0 {
		fallback += "; rejected: " + strings.Join(rejected, ", ")
	}
	return fileManager, fallback, nil
}

// scanResolvConfHeader walks /etc/resolv.conf header comments and returns the
// matching manager. If reason is empty the caller should pick file mode and
// use rejected for diagnostics.
func scanResolvConfHeader() (osManagerType, string, []string, error) {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return 0, "", nil, fmt.Errorf("unable to open %s for checking owner, got error: %w", defaultResolvConfPath, err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Errorf("close file %s: %s", defaultResolvConfPath, cerr)
		}
	}()

	var rejected []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		if text[0] != '#' {
			break
		}
		if mgr, reason, rej := matchResolvConfHeader(text); reason != "" {
			return mgr, reason, nil, nil
		} else if rej != "" {
			rejected = append(rejected, rej)
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return 0, "", nil, fmt.Errorf("scan: %w", err)
	}
	return 0, "", rejected, nil
}

// matchResolvConfHeader inspects a single comment line. Returns either a
// definitive (manager, reason) or a non-empty rejected diagnostic.
func matchResolvConfHeader(text string) (osManagerType, string, string) {
	if strings.Contains(text, fileGeneratedResolvConfContentHeader) {
		return netbirdManager, "netbird-managed resolv.conf header detected", ""
	}
	if strings.Contains(text, "NetworkManager") {
		if isDbusListenerRunning(networkManagerDest, networkManagerDbusObjectNode) && isNetworkManagerSupported() {
			return networkManager, "NetworkManager header + supported version on dbus", ""
		}
		return 0, "", "NetworkManager header (no dbus or unsupported version)"
	}
	if strings.Contains(text, "resolvconf") {
		if isSystemdResolveConfMode() {
			return systemdManager, "resolvconf header in systemd-resolved compatibility mode", ""
		}
		return resolvConfManager, "resolvconf header detected", ""
	}
	return 0, "", ""
}

// checkStub reports whether systemd-resolved's stub (127.0.0.53) is listed
// in /etc/resolv.conf. On parse failure we assume it is, to avoid dropping
// into file mode while resolved is active.
func checkStub() bool {
	rConf, err := parseDefaultResolvConf()
	if err != nil {
		log.Warnf("failed to parse resolv conf, assuming stub is active: %s", err)
		return true
	}

	systemdResolvedAddr := netip.AddrFrom4([4]byte{127, 0, 0, 53}) // 127.0.0.53
	for _, ns := range rConf.nameServers {
		if ns == systemdResolvedAddr {
			return true
		}
	}

	return false
}

// isLibnssResolveUsed reports whether nss-resolve is listed before dns on
// the hosts: line of /etc/nsswitch.conf. When it is, libc lookups are
// delegated to systemd-resolved regardless of /etc/resolv.conf.
func isLibnssResolveUsed() bool {
	bs, err := os.ReadFile(nsswitchConfPath)
	if err != nil {
		log.Debugf("read %s: %v", nsswitchConfPath, err)
		return false
	}
	return parseNsswitchResolveAhead(bs)
}

func parseNsswitchResolveAhead(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "hosts:" {
			continue
		}
		for _, module := range fields[1:] {
			switch module {
			case "dns":
				return false
			case "resolve":
				return true
			}
		}
	}
	return false
}
