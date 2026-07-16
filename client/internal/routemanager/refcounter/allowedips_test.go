package refcounter

import (
	"net/netip"
	"testing"
)

// fakeWG models WireGuard's cryptokey routing: a prefix can be installed on exactly one peer.
type fakeWG struct {
	installed map[netip.Prefix]string
	adds      int
	removes   int
}

func newFakeWG() *fakeWG {
	return &fakeWG{installed: map[netip.Prefix]string{}}
}

func (f *fakeWG) counter() *AllowedIPsRefCounter {
	return NewAllowedIPs(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			f.adds++
			f.installed[prefix] = peerKey
			return peerKey, nil
		},
		func(prefix netip.Prefix, peerKey string) error {
			f.removes++
			// only clear if this peer is the one installed, mirroring wg semantics
			if f.installed[prefix] == peerKey {
				delete(f.installed, prefix)
			}
			return nil
		},
	)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// TestAllowedIPs_SwapOnActivePeerRemoval reproduces the reported bug: two networks with the same
// prefix routed by different peers. Removing the network whose peer is installed must hand the
// prefix over to the surviving peer instead of leaving it on the removed one.
func TestAllowedIPs_SwapOnActivePeerRemoval(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	if _, err := c.Increment(p, "peerA"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Increment(p, "peerB"); err != nil {
		t.Fatal(err)
	}
	// First peer wins while both are present.
	if got := f.installed[p]; got != "peerA" {
		t.Fatalf("expected peerA installed, got %q", got)
	}

	// Remove the active peer's network -> must swap to peerB.
	if _, err := c.Decrement(p, "peerA"); err != nil {
		t.Fatal(err)
	}
	if got := f.installed[p]; got != "peerB" {
		t.Fatalf("BUG: prefix stuck on removed peer, want peerB got %q", got)
	}

	// Remove the last one -> prefix gone.
	if _, err := c.Decrement(p, "peerB"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.installed[p]; ok {
		t.Fatalf("expected prefix removed, still installed on %q", f.installed[p])
	}
}

// TestAllowedIPs_RemoveNonActivePeer removing a non-installed peer must not touch WireGuard.
func TestAllowedIPs_RemoveNonActivePeer(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	_, _ = c.Increment(p, "peerA")
	_, _ = c.Increment(p, "peerB")
	removesBefore := f.removes

	if _, err := c.Decrement(p, "peerB"); err != nil {
		t.Fatal(err)
	}
	if f.installed[p] != "peerA" {
		t.Fatalf("active peer must stay peerA, got %q", f.installed[p])
	}
	if f.removes != removesBefore {
		t.Fatalf("removing a non-active peer must not call wg remove")
	}
}

// TestAllowedIPs_SamePeerMultipleRefs two references via the same peer must keep the prefix until
// the last reference is released (the reason the per-peer count must be an int, not a set).
func TestAllowedIPs_SamePeerMultipleRefs(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	_, _ = c.Increment(p, "peerA")
	_, _ = c.Increment(p, "peerA")
	if f.adds != 1 {
		t.Fatalf("expected a single wg add for the same peer, got %d", f.adds)
	}

	if _, err := c.Decrement(p, "peerA"); err != nil {
		t.Fatal(err)
	}
	if f.installed[p] != "peerA" {
		t.Fatalf("prefix must stay while a reference remains, got %q", f.installed[p])
	}
	if f.removes != 0 {
		t.Fatalf("no wg remove expected while a reference remains, got %d", f.removes)
	}

	if _, err := c.Decrement(p, "peerA"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.installed[p]; ok {
		t.Fatalf("prefix must be removed after last reference")
	}
}

// TestAllowedIPs_RefCountAndActive checks the Ref returned to callers (used for the HA-disabled log).
func TestAllowedIPs_RefCountAndActive(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	ref, _ := c.Increment(p, "peerA")
	if ref.Count != 1 || ref.Out != "peerA" {
		t.Fatalf("want {1, peerA}, got {%d, %q}", ref.Count, ref.Out)
	}
	ref, _ = c.Increment(p, "peerB")
	if ref.Count != 2 || ref.Out != "peerA" {
		t.Fatalf("want {2, peerA}, got {%d, %q}", ref.Count, ref.Out)
	}
}

// TestAllowedIPs_Flush removes everything installed and clears the counter.
func TestAllowedIPs_Flush(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p1 := mustPrefix(t, "10.44.8.0/24")
	p2 := mustPrefix(t, "10.44.9.0/24")

	_, _ = c.Increment(p1, "peerA")
	_, _ = c.Increment(p2, "peerB")

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.installed) != 0 {
		t.Fatalf("expected all prefixes removed, got %v", f.installed)
	}
	// After flush, a fresh increment must add again.
	_, _ = c.Increment(p1, "peerC")
	if f.installed[p1] != "peerC" {
		t.Fatalf("counter not reset after flush")
	}
}
