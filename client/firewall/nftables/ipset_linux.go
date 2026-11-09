//go:build !android

package nftables

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

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
	if err := r.conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush error: %w", err)
	}
	log.Debugf("Created new ipset: %s with %d initial prefixes (total prefixes %d)", setName, len(initialElements)/2, len(prefixes))

	// The set is committed now. If a later batch fails, destroy it: the
	// refcounter records nothing on a create-callback error, so it would
	// otherwise leak, and a partial source set fails-open for deny rules.
	if err := r.addRemainingElements(nfset, elements, maxElements); err != nil {
		if derr := r.deleteIpSet(setName, nfset); derr != nil {
			log.Warnf("rollback ipset %s after add failure: %v", setName, derr)
		}
		return nil, err
	}

	log.Infof("Created new ipset: %s with %d prefixes", setName, len(prefixes))
	return nfset, nil
}

// addRemainingElements adds element batches beyond the initial one in
// maxElements-sized chunks, flushing each. Called after the set has been
// created with its first batch.
func (r *family) addRemainingElements(nfset *nftables.Set, elements []nftables.SetElement, maxElements int) error {
	nElements := len(elements)
	for subStart := maxElements; subStart < nElements; subStart += maxElements {
		subEnd := min(subStart+maxElements, nElements)
		subElement := elements[subStart:subEnd]
		nSubPrefixes := len(subElement) / 2
		log.Tracef("Adding new prefixes (%d) in ipset: %s", nSubPrefixes, nfset.Name)
		if err := r.conn.SetAddElements(nfset, subElement); err != nil {
			return fmt.Errorf("error adding prefixes (%d) to set %s: %w", nSubPrefixes, nfset.Name, err)
		}
		if err := r.conn.Flush(); err != nil {
			return fmt.Errorf("flush error: %w", err)
		}
		log.Debugf("Added new prefixes (%d) in ipset: %s", nSubPrefixes, nfset.Name)
	}
	return nil
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

func (r *family) deleteIpSet(setName string, nfset *nftables.Set) error {
	r.conn.DelSet(nfset)
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf(flushError, err)
	}

	log.Debugf("Deleted unused ipset %s", setName)
	return nil
}

func (r *family) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	nfset, err := r.conn.GetSetByName(r.workTable, set.HashedName())
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
		if err := r.conn.SetAddElements(nfset, elements[start:end]); err != nil {
			return fmt.Errorf("add elements to set %s: %w", set.HashedName(), err)
		}
		if err := r.conn.Flush(); err != nil {
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
