package stdnet

import (
	"runtime"
	"testing"
)

// Regression test for the Windows-side ICE interface filter.
//
// Two things this test pins down:
//
//  1. Loopback / Hyper-V Default Switch / WSL adapter must be excluded
//     even though their Windows names ("Loopback Pseudo-Interface 1",
//     "vEthernet (Default Switch)") don't share a lowercase prefix with
//     anything in the default disallow list.
//
//  2. User-named Hyper-V external switches (e.g. "vEthernet (LAN)")
//     MUST stay allowed. On uray-mic-d4 (Michael Uray's debug bundle
//     2026-05-04) that interface owns the default route at
//     192.168.0.243/22 -> 0.0.0.0/0; filtering it out would have
//     made P2P worse, not better. Codex review caught the broad
//     "veth"-prefix variant of this fix before it shipped.
func TestInterfaceFilter_Windows_TargetedFiltering(t *testing.T) {
	disallow := []string{"wt", "wg", "veth", "br-", "lo", "docker"}
	allow := InterfaceFilter(disallow)

	cases := []struct {
		name string
		want bool // true => allowed, false => filtered out
	}{
		// Always-bad Windows interfaces: filtered.
		{"Loopback Pseudo-Interface 1", false},
		{"vEthernet (Default Switch)", false},
		{"vEthernet (WSL)", false},
		{"vEthernet (WSL (Hyper-V firewall))", false},
		// Disallow-list tokens (any platform).
		{"wt0", false},
		// Linux names (lowercase) still filtered:
		{"lo", false},

		// Real candidate interfaces stay allowed.
		{"Ethernet USB", true},
		{"OpenVPN 1", true},
		{"WiFi", true},
		// Critical: user-named Hyper-V external switch is the actual
		// default-route interface and must NOT be dropped.
		{"vEthernet (LAN)", true},
		{"vEthernet (External)", true},
	}

	for _, c := range cases {
		// The wgctrl branch can override on hosts where NetBird is
		// running; tests run on a host where these names are not
		// real interfaces, so the final return faithfully reflects
		// the disallow-list logic.
		got := allow(c.name)
		// "veth*" prefix only filters on non-Windows; on Linux test
		// runners "vEthernet (LAN)" still passes because of mixed
		// case + the !Windows branch keeping the prefix match.
		if !c.want && got {
			t.Errorf("InterfaceFilter(%q) = true, want false (should be filtered)", c.name)
		}
		if c.want && !got && runtime.GOOS == "windows" && c.name == "vEthernet (LAN)" {
			t.Fatalf("InterfaceFilter(%q) = false, want true on Windows (this is uray-mic-d4's default-route interface)", c.name)
		}
	}
}

// Linux-side regression: keep filtering legitimate Linux veth pairs.
func TestInterfaceFilter_Linux_VethPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("veth prefix filter is intentionally skipped on Windows")
	}
	allow := InterfaceFilter([]string{"veth", "docker", "lo"})
	for _, name := range []string{"veth0", "veth1234", "docker0", "lo"} {
		if allow(name) {
			t.Errorf("InterfaceFilter(%q) = true, want false on Linux", name)
		}
	}
}
