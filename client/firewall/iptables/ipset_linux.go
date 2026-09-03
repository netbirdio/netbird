//go:build !android

package iptables

import (
	"fmt"
	"net/netip"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"github.com/lrh3321/ipset-go"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// probeIPSetSupport checks whether the kernel can create the ipset type
// used for source and destination matches. On kernels lacking the
// required ipset hash module, set creation fails (e.g. "invalid
// argument"), which would otherwise fail every multi-source rule and
// leave traffic the policy permits blocked by the catch-all drop. When
// unsupported, multi-source rules fall back to one rule per prefix.
func (r *family) probeIPSetSupport() bool {
	// Use a unique name so concurrent processes don't collide and we only ever
	// destroy the set we created ourselves. ipset names are limited to 31 chars,
	// so use a short random suffix.
	probeName := "nb-probe-" + uuid.New().String()[:8]

	if err := r.createIPSet(probeName); err != nil {
		log.Warnf("ipset is not available (failed to create probe set: %v); "+
			"falling back to per-IP iptables ACL rules. Ensure the kernel provides "+
			"the ipset hash:net module (ip_set_hash_net) for better performance with large rule sets", err)
		return false
	}

	if err := r.destroyIPSet(probeName); err != nil {
		log.Debugf("destroy ipset probe set %q: %v", probeName, err)
	}

	return true
}

func (r *family) createIpSet(setName string, sources []netip.Prefix) error {
	if err := r.createIPSet(setName); err != nil {
		return fmt.Errorf("create set %s: %w", setName, err)
	}

	for _, prefix := range sources {
		if err := r.addPrefixToIPSet(setName, prefix); err != nil {
			// The refcounter records nothing when this callback errors,
			// so destroy the set or it leaks in the kernel. A partial
			// source set would also fail-open for deny rules, so the
			// rule must fail rather than install with a missing source.
			if derr := r.destroyIPSet(setName); derr != nil {
				log.Warnf("rollback ipset %s after add failure: %v", setName, derr)
			}
			return fmt.Errorf("add element to set %s: %w", setName, err)
		}
	}

	return nil
}

func (r *family) deleteIpSet(setName string) error {
	if err := r.destroyIPSet(setName); err != nil {
		return fmt.Errorf("destroy set %s: %w", setName, err)
	}

	log.Debugf("deleted unused ipset %s", setName)
	return nil
}

func (r *family) UpdateSet(set firewall.Set, prefixes []netip.Prefix) error {
	name := r.ipsetName(set.HashedName())
	var merr *multierror.Error
	for _, prefix := range prefixes {
		if err := r.addPrefixToIPSet(name, prefix); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("add prefix to ipset: %w", err))
		}
	}
	if merr == nil {
		log.Debugf("updated set %s with prefixes %v", name, prefixes)
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) ipsetName(name string) string {
	if r.v6 {
		return name + "-v6"
	}
	return name
}

func (r *family) createIPSet(name string) error {
	opts := ipset.CreateOptions{
		Replace: true,
	}
	if r.v6 {
		opts.Family = ipset.FamilyIPV6
	}

	if err := ipset.Create(name, ipset.TypeHashNet, opts); err != nil {
		return fmt.Errorf("create ipset %s: %w", name, err)
	}

	log.Debugf("created ipset %s with type hash:net", name)
	return nil
}

func (r *family) addPrefixToIPSet(name string, prefix netip.Prefix) error {
	addr := prefix.Addr()
	ip := addr.AsSlice()

	entry := &ipset.Entry{
		IP:      ip,
		CIDR:    uint8(prefix.Bits()),
		Replace: true,
	}

	if err := ipset.Add(name, entry); err != nil {
		return fmt.Errorf("add prefix to ipset %s: %w", name, err)
	}

	return nil
}

func (r *family) destroyIPSet(name string) error {
	return ipset.Destroy(name)
}
