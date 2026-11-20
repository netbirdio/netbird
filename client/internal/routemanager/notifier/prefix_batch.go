package notifier

import "net/netip"

// prefixBatch holds prefix announcements back while a batch is open and releases
// only the newest one when the outermost batch closes. Not safe for concurrent
// use: the owning notifier serialises access under its own lock.
type prefixBatch struct {
	depth   int
	pending []netip.Prefix
	// held tells an announced empty set, which routing cleanup produces and
	// which must go out, apart from nothing having been announced at all.
	held bool
}

func (b *prefixBatch) begin() {
	b.depth++
}

// hold keeps prefixes for the end of the batch and reports whether it did;
// false means no batch is open and the caller announces immediately.
func (b *prefixBatch) hold(prefixes []netip.Prefix) bool {
	if b.depth == 0 {
		return false
	}
	b.pending = prefixes
	b.held = true
	return true
}

// end closes one batch level. It returns the newest held prefixes and true only
// when the outermost batch closes with something held.
func (b *prefixBatch) end() ([]netip.Prefix, bool) {
	if b.depth == 0 {
		return nil, false
	}
	b.depth--
	if b.depth > 0 || !b.held {
		return nil, false
	}
	pending := b.pending
	b.pending = nil
	b.held = false
	return pending, true
}
