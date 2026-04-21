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
	osManager, err := getOSDNSManagerType()
	if err != nil {
		return nil, fmt.Errorf("get os dns manager type: %w", err)
	}

	log.Infof("System DNS manager discovered: %s", osManager)
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

func getOSDNSManagerType() (osManagerType, error) {
	// Prefer systemd-resolved whenever it owns libc resolution, regardless of
	// who wrote /etc/resolv.conf. File-mode rewrites do not affect lookups
	// that go through nss-resolve, and in foreign mode they can loop back
	// through resolved as an upstream.
	if isSystemdResolvedRunning() && (isLibnssResolveUsed() || checkStub()) {
		return systemdManager, nil
	}

	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return 0, fmt.Errorf("unable to open %s for checking owner, got error: %w", defaultResolvConfPath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("close file %s: %s", defaultResolvConfPath, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		if text[0] != '#' {
			return fileManager, nil
		}
		if strings.Contains(text, fileGeneratedResolvConfContentHeader) {
			return netbirdManager, nil
		}
		if strings.Contains(text, "NetworkManager") && isDbusListenerRunning(networkManagerDest, networkManagerDbusObjectNode) && isNetworkManagerSupported() {
			return networkManager, nil
		}
		if strings.Contains(text, "resolvconf") {
			if isSystemdResolveConfMode() {
				return systemdManager, nil
			}

			return resolvConfManager, nil
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return 0, fmt.Errorf("scan: %w", err)
	}

	return fileManager, nil
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
