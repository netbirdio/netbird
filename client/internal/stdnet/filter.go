package stdnet

import (
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// windowsKnownBadSubstrings lists Windows interface-name fragments that
// should ALWAYS be excluded from ICE candidate gathering, even when the
// caller-supplied disallow list does not cover them. These are the
// interfaces uray-mic-d4's debug bundle (2026-05-04) showed Pion ICE
// picking as host candidates -- producing dead-end pairs because none
// of these can be reached from the public internet:
//
//   - "loopback pseudo-interface" -> 127.0.0.1 (loopback)
//   - "vethernet (default switch)" -> 172.26.x.x (Hyper-V NAT-only)
//   - "vethernet (wsl"             -> WSL2 host-only
//
// Matched as case-insensitive substrings.
//
// IMPORTANT: User-named Hyper-V external switches like "vEthernet (LAN)"
// MUST NOT be filtered. On uray-mic-d4 that interface IS the default
// route (192.168.0.243/22 -> 0.0.0.0/0 via 192.168.0.254). Filtering it
// out would actually break P2P, not improve it.
var windowsKnownBadSubstrings = []string{
	"loopback pseudo-interface",
	"vethernet (default switch)",
	"vethernet (wsl",
}

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them.
//
// Matching is case-insensitive because Windows interface names use mixed
// case (e.g. "Loopback Pseudo-Interface 1") while the disallow list is
// lowercase. Without the fold, the historic implementation let every
// Windows interface slip past and Pion ICE picked junk addresses
// (127.0.0.1, 172.26.x.x Hyper-V Default Switch, internal-VPN /22s) as
// local host candidates, dooming P2P to dead-end pairs and forcing
// relay-only. See windowsKnownBadSubstrings for the targeted Windows
// extras.
//
// Reported by Michael Uray on uray-mic-d4 (2026-05-04): 0/28 peers P2P.
func InterfaceFilter(disallowList []string) func(string) bool {
	return func(iFace string) bool {
		lowerIFace := strings.ToLower(iFace)

		// Linux/macOS loopback prefix ("lo", "lo0").
		if strings.HasPrefix(lowerIFace, "lo") {
			return false
		}

		// Windows-specific known-bad substrings (loopback, NAT switches).
		if runtime.GOOS == "windows" {
			for _, sub := range windowsKnownBadSubstrings {
				if strings.Contains(lowerIFace, sub) {
					return false
				}
			}
		}

		for _, s := range disallowList {
			sLower := strings.ToLower(s)
			// "veth" exists on both Linux (legitimate veth pair to filter)
			// and Windows (where every Hyper-V iface starts with vEthernet,
			// including the user's REAL default-route external switch). On
			// Windows, junk Hyper-V interfaces are filtered above by name;
			// applying a blanket vEthernet* prefix here would also drop
			// user-named external switches like "vEthernet (LAN)".
			if sLower == "veth" && runtime.GOOS == "windows" {
				continue
			}
			if strings.HasPrefix(lowerIFace, sLower) && runtime.GOOS != "ios" {
				return false
			}
		}
		// look for unlisted WireGuard interfaces
		wg, err := wgctrl.New()
		if err != nil {
			log.Debugf("trying to create a wgctrl client failed with: %v", err)
			return true
		}
		defer func() {
			_ = wg.Close()
		}()

		_, err = wg.Device(iFace)
		return err != nil
	}
}
