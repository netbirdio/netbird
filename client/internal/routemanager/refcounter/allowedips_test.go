package refcounter

import (
	"errors"
	"net/netip"
	"testing"
)

// fakeWG models WireGuard's cryptokey routing: a prefix can be installed on exactly one peer.
// failAdd/failRemove make the next add/remove fail once, to exercise the self-healing error paths.
type fakeWG struct {
	installed  map[netip.Prefix]string
	adds       int
	removes    int
	failAdd    bool
	failRemove bool
}

func newFakeWG() *fakeWG {
	return &fakeWG{installed: map[netip.Prefix]string{}}
}

func (f *fakeWG) counter() *AllowedIPsRefCounter {
	return NewAllowedIPs(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			if f.failAdd {
				f.failAdd = false
				return "", errors.New("add failed")
			}
			f.adds++
			f.installed[prefix] = peerKey
			return peerKey, nil
		},
		func(prefix netip.Prefix, peerKey string) error {
			if f.failRemove {
				f.failRemove = false
				return errors.New("remove failed")
			}
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

func mustIncrement(t *testing.T, c *AllowedIPsRefCounter, p netip.Prefix, peer string) Ref[string] {
	t.Helper()
	ref, err := c.Increment(p, peer)
	if err != nil {
		t.Fatalf("Increment(%v, %s): %v", p, peer, err)
	}
	return ref
}

func mustDecrement(t *testing.T, c *AllowedIPsRefCounter, p netip.Prefix, peer string) Ref[string] {
	t.Helper()
	ref, err := c.Decrement(p, peer)
	if err != nil {
		t.Fatalf("Decrement(%v, %s): %v", p, peer, err)
	}
	return ref
}

// TestAllowedIPs_SwapOnActivePeerRemoval reproduces the reported bug: two networks with the same
// prefix routed by different peers. Removing the network whose peer is installed must hand the
// prefix over to the surviving peer instead of leaving it on the removed one.
func TestAllowedIPs_SwapOnActivePeerRemoval(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	mustIncrement(t, c, p, "peerA")
	mustIncrement(t, c, p, "peerB")
	// First peer wins while both are present.
	if got := f.installed[p]; got != "peerA" {
		t.Fatalf("expected peerA installed, got %q", got)
	}

	// Remove the active peer's network -> must swap to peerB.
	mustDecrement(t, c, p, "peerA")
	if got := f.installed[p]; got != "peerB" {
		t.Fatalf("BUG: prefix stuck on removed peer, want peerB got %q", got)
	}

	// Remove the last one -> prefix gone.
	mustDecrement(t, c, p, "peerB")
	if _, ok := f.installed[p]; ok {
		t.Fatalf("expected prefix removed, still installed on %q", f.installed[p])
	}
}

// TestAllowedIPs_RemoveNonActivePeer removing a non-installed peer must not touch WireGuard.
func TestAllowedIPs_RemoveNonActivePeer(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	mustIncrement(t, c, p, "peerA")
	mustIncrement(t, c, p, "peerB")
	removesBefore := f.removes

	mustDecrement(t, c, p, "peerB")
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

	mustIncrement(t, c, p, "peerA")
	mustIncrement(t, c, p, "peerA")
	if f.adds != 1 {
		t.Fatalf("expected a single wg add for the same peer, got %d", f.adds)
	}

	mustDecrement(t, c, p, "peerA")
	if f.installed[p] != "peerA" {
		t.Fatalf("prefix must stay while a reference remains, got %q", f.installed[p])
	}
	if f.removes != 0 {
		t.Fatalf("no wg remove expected while a reference remains, got %d", f.removes)
	}

	mustDecrement(t, c, p, "peerA")
	if _, ok := f.installed[p]; ok {
		t.Fatalf("prefix must be removed after last reference")
	}
}

// TestAllowedIPs_RefCountAndActive checks the Ref returned to callers (used for the HA-disabled log).
func TestAllowedIPs_RefCountAndActive(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	ref := mustIncrement(t, c, p, "peerA")
	if ref.Count != 1 || ref.Out != "peerA" {
		t.Fatalf("want {1, peerA}, got {%d, %q}", ref.Count, ref.Out)
	}
	ref = mustIncrement(t, c, p, "peerB")
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

	mustIncrement(t, c, p1, "peerA")
	mustIncrement(t, c, p2, "peerB")

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.installed) != 0 {
		t.Fatalf("expected all prefixes removed, got %v", f.installed)
	}
	// After flush, a fresh increment must add again.
	mustIncrement(t, c, p1, "peerC")
	if f.installed[p1] != "peerC" {
		t.Fatalf("counter not reset after flush")
	}
}

// TestAllowedIPs_SelfHealAfterSwapAddError ensures a failed add during a swap does not permanently
// strand the prefix: the next Decrement (or Increment) must retry and install a surviving peer.
func TestAllowedIPs_SelfHealAfterSwapAddError(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	mustIncrement(t, c, p, "peerA")
	mustIncrement(t, c, p, "peerB")
	mustIncrement(t, c, p, "peerC")

	// Removing the active peerA triggers a swap to a survivor; make the add fail once.
	f.failAdd = true
	if _, err := c.Decrement(p, "peerA"); err == nil {
		t.Fatalf("expected error from failed swap add")
	}
	if _, ok := f.installed[p]; ok {
		t.Fatalf("nothing should be installed after a failed swap add, got %q", f.installed[p])
	}

	// A later Decrement of a non-active survivor must retry the hand-off (self-heal), not stay stuck.
	ref := mustDecrement(t, c, p, "peerC")
	if got := f.installed[p]; got == "" {
		t.Fatalf("self-heal failed: prefix left unrouted after add recovered")
	}
	if ref.Out == "" {
		t.Fatalf("expected an active peer after self-heal, got empty")
	}
}

// TestAllowedIPs_SelfHealAfterRemoveError ensures a failed remove during a swap is retried instead
// of leaving e.active stuck on a peer that no longer holds references.
func TestAllowedIPs_SelfHealAfterRemoveError(t *testing.T) {
	f := newFakeWG()
	c := f.counter()
	p := mustPrefix(t, "10.44.8.0/24")

	mustIncrement(t, c, p, "peerA")
	mustIncrement(t, c, p, "peerB")

	// Releasing active peerA must detach it (remove) then add peerB; fail the remove once.
	f.failRemove = true
	if _, err := c.Decrement(p, "peerA"); err == nil {
		t.Fatalf("expected error from failed remove")
	}

	// Next Decrement of the non-active survivor retries: removes stale peerA, installs peerB.
	mustDecrement(t, c, p, "peerB")
	// peerB had only one ref, so after retry the prefix is fully released.
	if _, ok := f.installed[p]; ok {
		t.Fatalf("expected prefix released after self-heal, still on %q", f.installed[p])
	}
}
