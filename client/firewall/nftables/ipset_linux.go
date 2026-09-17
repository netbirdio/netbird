//go:build !android

package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

func (r *family) getIpSet(set firewall.Set, prefixes []netip.Prefix, isSource bool) ([]expr.Any, error) {
	ref, err := r.ipsetCounter.Increment(set.HashedName(), setInput{
		set:      set,
		prefixes: prefixes,
	})
	if err != nil {
		return nil, fmt.Errorf("create or get ipset: %w", err)
	}

	return r.getIpSetExprs(ref, isSource)
}

// createIpSet queues a named interval set on conn. The caller must flush
// conn together with the rule that looks the set up: NFTA_LOOKUP_SET_ID is
// valid only in that transaction. Overflow elements are stored for
// commitPendingSetElements after that flush.
func (r *family) createIpSet(setName string, input setInput) (*nftables.Set, error) {
	// overlapping prefixes will result in an error, so we need to merge them
	prefixes := firewall.MergeIPRanges(input.prefixes)

	nfset := &nftables.Set{
		Name:    setName,
		Comment: input.set.Comment(),
		Table:   r.workTable,
		// required for prefixes
		Interval: true,
		KeyType:  r.af.setKeyType,
	}

	elements := r.convertPrefixesToSet(prefixes)
	nElements := len(elements)

	maxElements := maxPrefixesSet * 2
	initialElements := elements[:min(maxElements, nElements)]

	if err := r.conn.AddSet(nfset, initialElements); err != nil {
		return nil, fmt.Errorf("error adding set %s: %w", setName, err)
	}
	if nElements > maxElements {
		r.pendingSetElements[setName] = pendingSetUpdate{
			set:      nfset,
			elements: elements[maxElements:],
		}
	}

	log.Debugf("Queued new ipset: %s with %d initial prefixes (total prefixes %d)", setName, len(initialElements)/2, len(prefixes))
	log.Infof("Created new ipset: %s with %d prefixes", setName, len(prefixes))
	return nfset, nil
}

// commitPendingSetElements writes every overflow chunk that did not fit in
// a rule batch. The named set must already exist in the kernel. Callers
// that installed a specific rule should use commitPendingSets with the
// names that call queued so an unrelated leftover cannot fail them.
func (r *family) commitPendingSetElements() error {
	names := make([]string, 0, len(r.pendingSetElements))
	for name := range r.pendingSetElements {
		names = append(names, name)
	}
	return r.commitPendingSets(names)
}

// commitPendingSets writes overflow chunks for the named sets, retrying
// immediately a few times. Entries stay in the map until their batches
// succeed so a retry does not replay prefixes that already landed.
func (r *family) commitPendingSets(names []string) error {
	if len(names) == 0 {
		return nil
	}
	var err error
	for attempt := 1; attempt <= pendingSetCommitAttempts; attempt++ {
		err = r.commitPendingSetsOnce(names)
		if err == nil {
			return nil
		}
		log.Debugf("commit pending ipset elements attempt %d/%d: %v", attempt, pendingSetCommitAttempts, err)
	}
	return err
}

func (r *family) commitPendingSetsOnce(names []string) error {
	maxElements := maxPrefixesSet * 2
	var merr *multierror.Error
	for _, setName := range names {
		p, ok := r.pendingSetElements[setName]
		if !ok {
			continue
		}
		left, err := r.addElementBatches(p.set, p.elements, maxElements)
		if err != nil {
			r.pendingSetElements[setName] = pendingSetUpdate{set: p.set, elements: left}
			merr = multierror.Append(merr, fmt.Errorf("add remaining elements to set %s: %w", setName, err))
			continue
		}
		delete(r.pendingSetElements, setName)
	}
	return nberrors.FormatErrorOrNil(merr)
}

// commitOverflowOrRollback commits overflow for sets used by the current
// Add*. On failure after retries it rolls the live rule back. Pending
// overflow is discarded only when that rollback deletes the rule; otherwise
// the suffix is kept so a retry can finish the set instead of reusing a
// truncated one.
func (r *family) commitOverflowOrRollback(queued []string, rollback func() bool) error {
	if err := r.commitPendingSets(queued); err != nil {
		if rollback() {
			r.discardPendingSets(queued)
		}
		return fmt.Errorf("add remaining ipset elements: %w", err)
	}
	return nil
}

func (r *family) pendingSetSnapshot() map[string]struct{} {
	snap := make(map[string]struct{}, len(r.pendingSetElements))
	for name := range r.pendingSetElements {
		snap[name] = struct{}{}
	}
	return snap
}

func (r *family) pendingAddedSince(before map[string]struct{}) []string {
	var names []string
	for name := range r.pendingSetElements {
		if _, ok := before[name]; !ok {
			names = append(names, name)
		}
	}
	return names
}

func (r *family) pendingForExprs(exprsList ...[]expr.Any) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, exprs := range exprsList {
		for _, e := range exprs {
			lookup, ok := e.(*expr.Lookup)
			if !ok || lookup.SetName == "" {
				continue
			}
			if _, pending := r.pendingSetElements[lookup.SetName]; !pending {
				continue
			}
			if _, dup := seen[lookup.SetName]; dup {
				continue
			}
			seen[lookup.SetName] = struct{}{}
			names = append(names, lookup.SetName)
		}
	}
	return names
}

// discardPendingSets removes overflow queued for the given set names.
// Unrelated pending work is left in place.
func (r *family) discardPendingSets(names []string) {
	for _, name := range names {
		delete(r.pendingSetElements, name)
	}
}

func (r *family) discardPendingSetElements() {
	r.pendingSetElements = make(map[string]pendingSetUpdate)
}

// addElementBatches adds elements in maxElements-sized chunks on sConn.
// On error it returns the uncommitted suffix so a retry does not replay
// batches that already landed.
func (r *family) addElementBatches(nfset *nftables.Set, elements []nftables.SetElement, maxElements int) ([]nftables.SetElement, error) {
	nElements := len(elements)
	for subStart := 0; subStart < nElements; subStart += maxElements {
		subEnd := min(subStart+maxElements, nElements)
		subElement := elements[subStart:subEnd]
		nSubPrefixes := len(subElement) / 2
		log.Tracef("Adding new prefixes (%d) in ipset: %s", nSubPrefixes, nfset.Name)
		if err := r.sConn.SetAddElements(nfset, subElement); err != nil {
			return elements[subStart:], fmt.Errorf("error adding prefixes (%d) to set %s: %w", nSubPrefixes, nfset.Name, err)
		}
		if err := r.flushSetElements(); err != nil {
			return elements[subStart:], fmt.Errorf(flushError, err)
		}
		log.Debugf("Added new prefixes (%d) in ipset: %s", nSubPrefixes, nfset.Name)
	}
	return nil, nil
}

func (r *family) flushSetElements() error {
	if r.testPendingFlush != nil {
		return r.testPendingFlush()
	}
	return r.sConn.Flush()
}

func (r *family) convertPrefixesToSet(prefixes []netip.Prefix) []nftables.SetElement {
	var elements []nftables.SetElement
	for _, prefix := range prefixes {
		// nftables needs half-open intervals [firstIP, lastIP) for prefixes
		// e.g. 10.0.0.0/24 becomes [10.0.0.0, 10.0.1.0), 10.1.1.1/32 becomes [10.1.1.1, 10.1.1.2) etc
		firstIP := prefix.Addr()

		// For a /0 the last address is the broadcast and its Next() overflows
		// to an invalid Addr with an empty key, so wrap to the zero address,
		// which nftables reads as the open end of a full-range interval.
		var lastKey []byte
		if prefix.Bits() == 0 {
			lastKey = make([]byte, r.af.addrLen)
		} else {
			lastKey = calculateLastIP(prefix).Next().AsSlice()
		}

		// the nft tool also adds a zero-address IntervalEnd element, see https://github.com/google/nftables/issues/247
		// nftables.SetElement{Key: make([]byte, r.af.addrLen), IntervalEnd: true},
		elements = append(elements,
			nftables.SetElement{Key: firstIP.AsSlice()},
			nftables.SetElement{Key: lastKey, IntervalEnd: true},
		)
	}
	return elements
}

// calculateLastIP determines the last IP in a given prefix.
func calculateLastIP(prefix netip.Prefix) netip.Addr {
	masked := prefix.Masked()
	if masked.Addr().Is4() {
		hostMask := ^uint32(0) >> masked.Bits()
		lastIP := uint32FromNetipAddr(masked.Addr()) | hostMask
		return netip.AddrFrom4(uint32ToBytes(lastIP))
	}

	// IPv6: set host bits to all 1s
	b := masked.Addr().As16()
	bits := masked.Bits()
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom16(b)
}

// Utility function to convert netip.Addr to uint32.
func uint32FromNetipAddr(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Utility function to convert uint32 to a netip-compatible byte slice.
func uint32ToBytes(ip uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip)
	return b
}

// deleteIpSet removes a named set from the kernel via sConn, the dedicated
// set connection.
func (r *family) deleteIpSet(setName string, nfset *nftables.Set) error {
	r.sConn.DelSet(nfset)
	if err := r.sConn.Flush(); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf(flushError, err)
	}

	log.Debugf("Deleted unused ipset %s", setName)
	return nil
}

// UpdateSet adds prefixes to an existing named set, batching large updates
// into multiple commits on sConn, the dedicated set connection.
func (r *family) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	nfset, err := r.sConn.GetSetByName(r.workTable, set.HashedName())
	if err != nil {
		return fmt.Errorf("get set %s: %w", set.HashedName(), err)
	}

	// Overlapping prefixes (e.g. duplicate resolved addresses) make the
	// interval set reject the batch, so merge them as createIpSet does.
	prefixes = firewall.MergeIPRanges(prefixes)
	elements := r.convertPrefixesToSet(prefixes)

	// Add in batches sized like createIpSet so a large update does not
	// exceed the netlink message size limit.
	maxElements := maxPrefixesSet * 2
	for start := 0; start < len(elements); start += maxElements {
		end := min(start+maxElements, len(elements))
		if err := r.sConn.SetAddElements(nfset, elements[start:end]); err != nil {
			return fmt.Errorf("add elements to set %s: %w", set.HashedName(), err)
		}
		if err := r.sConn.Flush(); err != nil {
			return fmt.Errorf(flushError, err)
		}
	}

	log.Debugf("updated set %s with %d prefixes", set.HashedName(), len(prefixes))

	return nil
}

func (r *family) getIpSetExprs(ref refcounter.Ref[*nftables.Set], isSource bool) ([]expr.Any, error) {
	// dst offset by default
	offset := r.af.dstAddrOffset
	if isSource {
		// src offset
		offset = r.af.srcAddrOffset
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          r.af.addrLen,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        ref.Out.Name,
			SetID:          ref.Out.ID,
		},
	}, nil
}
