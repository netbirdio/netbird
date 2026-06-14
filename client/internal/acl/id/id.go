package id

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"github.com/netbirdio/netbird/client/firewall/manager"
)

// RuleID aliases manager.RuleID so existing nbid.RuleID references
// keep working while the canonical type lives in the firewall package.
type RuleID = manager.RuleID

// GenerateRuleID returns a deterministic content hash identifying a filter rule.
func GenerateRuleID(
	sources []netip.Prefix,
	destination manager.Network,
	proto manager.Protocol,
	sPort *manager.Port,
	dPort *manager.Port,
	action manager.Action,
) RuleID {
	sources = slices.Clone(sources)
	manager.SortPrefixes(sources)

	h := sha256.New()

	// Write all fields to the hasher, with delimiters
	h.Write([]byte("sources:"))
	for _, src := range sources {
		h.Write([]byte(src.String()))
		h.Write([]byte(","))
	}

	h.Write([]byte("destination:"))
	h.Write([]byte(destination.String()))

	h.Write([]byte("proto:"))
	h.Write([]byte(proto))

	h.Write([]byte("sPort:"))
	if sPort != nil {
		h.Write([]byte(sPort.String()))
	} else {
		h.Write([]byte("<nil>"))
	}

	h.Write([]byte("dPort:"))
	if dPort != nil {
		h.Write([]byte(dPort.String()))
	} else {
		h.Write([]byte("<nil>"))
	}

	h.Write([]byte("action:"))
	h.Write([]byte(strconv.Itoa(int(action))))
	hash := hex.EncodeToString(h.Sum(nil))

	// prepend destination prefix to be able to identify the rule
	return RuleID(fmt.Sprintf("%s-%s", destination.String(), hash[:16]))
}
