package iptables

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
)

var ifaceMock = &iFaceMock{
	NameFunc: func() string {
		return "lo"
	},
	AddressFunc: func() iface.WGAddress {
		return iface.WGAddress{
			IP: net.ParseIP("10.20.0.1"),
			Network: &net.IPNet{
				IP:   net.ParseIP("10.20.0.0"),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		}
	},
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMock struct {
	NameFunc    func() string
	AddressFunc func() iface.WGAddress
}

func (i *iFaceMock) Name() string {
	if i.NameFunc != nil {
		return i.NameFunc()
	}
	panic("NameFunc is not set")
}

func (i *iFaceMock) Address() iface.WGAddress {
	if i.AddressFunc != nil {
		return i.AddressFunc()
	}
	panic("AddressFunc is not set")
}

func (i *iFaceMock) IsUserspaceBind() bool { return false }

func TestIptablesManager(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	// just check on the local interface
	manager, err := Create(ifaceMock)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Reset(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{
			Values: []int{8043: 8046},
		}
		rule2, err = manager.AddPeerFiltering(ip, "tcp", port, nil, fw.ActionAccept, "", "accept HTTPS traffic from ports range")
		require.NoError(t, err, "failed to add rule")

		for _, r := range rule2 {
			rr := r.(*Rule)
			checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")
		}

		require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{Values: []int{5353}}
		_, err = manager.AddPeerFiltering(ip, "udp", nil, port, fw.ActionAccept, "", "accept Fake DNS traffic")
		require.NoError(t, err, "failed to add rule")

		err = manager.Reset(nil)
		require.NoError(t, err, "failed to reset")

		ok, err := ipv4Client.ChainExists("filter", chainNameInputRules)
		require.NoError(t, err, "failed check chain exists")

		if ok {
			require.NoErrorf(t, err, "chain '%v' still exists after Reset", chainNameInputRules)
		}
	})
}

func TestIptablesManagerIPSet(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "lo"
		},
		AddressFunc: func() iface.WGAddress {
			return iface.WGAddress{
				IP: net.ParseIP("10.20.0.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("10.20.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			}
		},
	}

	// just check on the local interface
	manager, err := Create(mock)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Reset(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{
			Values: []int{443},
		}
		rule2, err = manager.AddPeerFiltering(ip, "tcp", port, nil, fw.ActionAccept, "default", "accept HTTPS traffic from ports range")
		for _, r := range rule2 {
			require.NoError(t, err, "failed to add rule")
			require.Equal(t, r.(*Rule).ipsetName, "default-sport", "ipset name must be set")
			require.Equal(t, r.(*Rule).ip, "10.20.0.3", "ipset IP must be set")
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")

			require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
		}
	})

	t.Run("reset check", func(t *testing.T) {
		err = manager.Reset(nil)
		require.NoError(t, err, "failed to reset")
	})
}

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, chainName string, mustExists bool, rulespec ...string) {
	t.Helper()
	exists, err := ipv4Client.Exists("filter", chainName, rulespec...)
	require.NoError(t, err, "failed to check rule")
	require.Falsef(t, !exists && mustExists, "rule '%v' does not exist", rulespec)
	require.Falsef(t, exists && !mustExists, "rule '%v' exist", rulespec)
}

func TestIptablesCreatePerformance(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "lo"
		},
		AddressFunc: func() iface.WGAddress {
			return iface.WGAddress{
				IP: net.ParseIP("10.20.0.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("10.20.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			}
		},
	}

	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create(mock)
			require.NoError(t, err)
			require.NoError(t, manager.Init(nil))
			time.Sleep(time.Second)

			defer func() {
				err := manager.Reset(nil)
				require.NoError(t, err, "clear the manager state")

				time.Sleep(time.Second)
			}()

			require.NoError(t, err)

			ip := net.ParseIP("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []int{1000 + i}}
				_, err = manager.AddPeerFiltering(ip, "tcp", nil, port, fw.ActionAccept, "", "accept HTTP traffic")

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
