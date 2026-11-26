package iptables

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// The state that crash cleanup reads is the entries map of each family. The deny-only family
// seeds its INPUT and FORWARD drops there, so a v4-only overlay still leaves IPv6 state that
// makes the cleanup treat a failure to reach ip6tables as an error and keep the state.
func TestShutdownState_FilterOnlyFamilyLeavesIPv6State(t *testing.T) {
	only := &family{wgIface: filterOnlyIface{}, entries: make(aclEntries), optionalEntries: make(map[chainKey][]entry), filterOnly: true, v6: true}
	only.seedInitialEntries()

	state := &ShutdownState{
		InterfaceState: &InterfaceState{NameStr: "wt-fo", WGAddress: wgaddr.Address{}},
		ACLEntries6:    only.entries,
	}
	assert.True(t, state.hasIPv6State(), "the deny-only family must be recorded in the state")

	empty := &ShutdownState{InterfaceState: &InterfaceState{NameStr: "wt-fo"}}
	assert.False(t, empty.hasIPv6State(), "a run that set up nothing for IPv6 leaves no IPv6 state")
}

func TestShutdownState_V6CreateFailure(t *testing.T) {
	cause := errors.New("ip6tables unavailable")

	t.Run("previous run installed IPv6 rules", func(t *testing.T) {
		state := &ShutdownState{
			InterfaceState: &InterfaceState{NameStr: "wt-fo"},
			ACLEntries6:    aclEntries{chainInput: {ruleSpec{"-i", "wt-fo", "-j", "DROP"}}},
		}
		err := state.v6CreateFailure(cause)
		require.Error(t, err, "the cleanup must fail so the state is kept and retried")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("previous run left nothing for IPv6", func(t *testing.T) {
		state := &ShutdownState{InterfaceState: &InterfaceState{NameStr: "wt-fo"}}
		assert.NoError(t, state.v6CreateFailure(cause), "nothing to remove, so the IPv4 cleanup carries on")
	})
}
