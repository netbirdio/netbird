package iface

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"io/ioutil"
)

// Configure routing and IP masquerading
//todo more docs on what exactly happens here and why it is needed
func ConfigureNAT(primaryIface string) error {
	log.Debugf("adding NAT / IP masquerading using nftables")
	ns, err := netns.Get()
	if err != nil {
		return err
	}

	conn := nftables.Conn{NetNS: int(ns)}

	log.Debugf("flushing nftable rulesets")
	conn.FlushRuleset()

	log.Debugf("setting up nftable rules for ip masquerading")

	nat := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	post := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	conn.AddRule(&nftables.Rule{
		Table: nat,
		Chain: post,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(primaryIface),
			},
			&expr.Masq{},
		},
	})

	if err := conn.Flush(); err != nil {
		return err
	}

	return nil
}

// Enables IP forwarding system property.
// Mostly used when you setup one peer as a VPN server.
func EnableIPForward() error {
	f := "/proc/sys/net/ipv4/ip_forward"

	content, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	if string(content) == "0\n" {
		log.Info("enabling IP Forward")
		return ioutil.WriteFile(f, []byte("1"), 0600)
	}

	return nil
}
