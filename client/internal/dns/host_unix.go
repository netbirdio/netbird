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
	// If systemd-resolved is serving on 127.0.0.53, prefer it regardless of
	// who owns /etc/resolv.conf. NetworkManager often rewrites resolv.conf with
	// its own header while still deferring resolution to systemd-resolved, and
	// falling back to file mode there snapshots 127.0.0.53 as the fallback
	// upstream. systemd-resolved in foreign mode re-reads /etc/resolv.conf and
	// ingests our address as global DNS, which closes the loop.
	if isSystemdResolvedRunning() && checkStub() {
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

// checkStub reports whether systemd-resolved's stub address (127.0.0.53) is
// listed in /etc/resolv.conf. A true return value signals that callers should
// prefer systemd-resolved; it does not make the final manager decision by
// itself (non-stub systems still fall through to the header scanner).
// On parse failure we assume the stub is present to avoid dropping into file
// mode while resolved is active, which would re-ingest NetBird's address as
// an upstream and form a resolution loop.
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
