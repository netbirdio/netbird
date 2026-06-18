package internal

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/peer"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

// reconcileIPv6 / updateConfig regression suite. Locks down the behavior that
// PR #5631 (main-side IPv6 overlay support) accidentally broke for embedded
// netstack clients: any first NetworkMap update that brings an IPv6 address
// used to trigger ErrResetConnection, which destroys the netstack and orphans
// every listener bound on it (proxy-side inbound listeners in particular).
// The fix in reconcileIPv6 distinguishes "v6 first-assigned" (apply in place)
// from "v6 swapped value" (must reset).

func mustEncodeV6Prefix(t *testing.T, p netip.Prefix) []byte {
	t.Helper()
	b, err := netiputil.EncodePrefix(p)
	require.NoError(t, err, "encode v6 prefix %s", p)
	return b
}

// reconcileIPv6Fixture builds the smallest Engine the function under test
// needs: a config (with WgAddr being the load-bearing field) and a wgInterface
// whose UpdateAddr call we can observe.
func reconcileIPv6Fixture(t *testing.T, initial wgaddr.Address) (*Engine, *MockWGIface, *wgaddr.Address) {
	t.Helper()
	var applied wgaddr.Address
	mock := &MockWGIface{
		AddressFunc: func() wgaddr.Address { return initial },
		UpdateAddrFunc: func(a wgaddr.Address) error {
			applied = a
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := &Engine{
		ctx:         ctx,
		clientCtx:   ctx,
		clientCancel: cancel,
		config:      &EngineConfig{WgAddr: initial},
		wgInterface: mock,
		syncMsgMux:  &sync.Mutex{},
	}
	return e, mock, &applied
}

func TestReconcileIPv6_FirstAssignment_AppliesInPlace(t *testing.T) {
	// Embedded clients boot v4-only; management later assigns a v6 overlay.
	// The fix: apply v6 in place, return reset=false. Pre-fix this case
	// fell through to the "v6 changed" branch and reset the engine.
	v4 := wgaddr.MustParseWGAddress("100.64.0.1/16")
	e, mock, applied := reconcileIPv6Fixture(t, v4)

	v6Prefix := netip.MustParsePrefix("fd00::1/64")
	conf := &mgmtProto.PeerConfig{
		Address:    v4.String(),
		AddressV6:  mustEncodeV6Prefix(t, v6Prefix),
	}

	reset, err := e.reconcileIPv6(conf)
	require.NoError(t, err)
	assert.False(t, reset, "first v6 assignment must NOT request an engine reset")

	require.True(t, e.config.WgAddr.HasIPv6(), "engine config must record the new v6")
	assert.Equal(t, v6Prefix.Addr(), e.config.WgAddr.IPv6, "engine config v6 address must match")
	assert.Equal(t, v6Prefix.Masked(), e.config.WgAddr.IPv6Net, "engine config v6 prefix must match")

	require.True(t, applied.HasIPv6(), "WGIface.UpdateAddr must be called with v6 populated")
	assert.Equal(t, v6Prefix.Addr(), applied.IPv6, "UpdateAddr must carry the new v6")
	_ = mock
}

func TestReconcileIPv6_NoChange_NoOp(t *testing.T) {
	// Steady state: management redelivers the same PeerConfig. No interface
	// mutation, no reset. Guards against an infinite reset loop if the
	// comparison ever drifts (e.g. address-vs-prefix masking bugs).
	v6Prefix := netip.MustParsePrefix("fd00::1/64")
	addr := wgaddr.MustParseWGAddress("100.64.0.1/16")
	require.NoError(t, addr.SetIPv6FromCompact(mustEncodeV6Prefix(t, v6Prefix)))

	updateAddrCalled := false
	mock := &MockWGIface{
		AddressFunc: func() wgaddr.Address { return addr },
		UpdateAddrFunc: func(a wgaddr.Address) error {
			updateAddrCalled = true
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx:         ctx,
		clientCtx:   ctx,
		clientCancel: cancel,
		config:      &EngineConfig{WgAddr: addr},
		wgInterface: mock,
		syncMsgMux:  &sync.Mutex{},
	}

	conf := &mgmtProto.PeerConfig{
		Address:   addr.String(),
		AddressV6: mustEncodeV6Prefix(t, v6Prefix),
	}
	reset, err := e.reconcileIPv6(conf)
	require.NoError(t, err)
	assert.False(t, reset, "unchanged v6 must NOT trigger reset")
	assert.False(t, updateAddrCalled, "unchanged v6 must NOT call UpdateAddr")
}

func TestReconcileIPv6_Removed_AppliesInPlace(t *testing.T) {
	// Management withdraws v6 (e.g. account toggled off the v6 group).
	// Cleared in place, no reset.
	v6Prefix := netip.MustParsePrefix("fd00::1/64")
	addr := wgaddr.MustParseWGAddress("100.64.0.1/16")
	require.NoError(t, addr.SetIPv6FromCompact(mustEncodeV6Prefix(t, v6Prefix)))

	e, _, applied := reconcileIPv6Fixture(t, addr)
	e.config.WgAddr = addr

	conf := &mgmtProto.PeerConfig{
		Address:   addr.String(),
		AddressV6: nil,
	}
	reset, err := e.reconcileIPv6(conf)
	require.NoError(t, err)
	assert.False(t, reset, "v6 removed must NOT trigger reset")

	assert.False(t, e.config.WgAddr.HasIPv6(), "engine config must reflect v6 cleared")
	assert.False(t, applied.HasIPv6(), "UpdateAddr must receive cleared v6")
}

func TestReconcileIPv6_PrefixLengthChanged_RequestsReset(t *testing.T) {
	// Same v6 host, different mask (e.g. /64 → /80). Treated like a value
	// change because the new netmask redefines the broadcast/scope.
	oldPrefix := netip.MustParsePrefix("fd00::1/64")
	newPrefix := netip.MustParsePrefix("fd00::1/80")

	addr := wgaddr.MustParseWGAddress("100.64.0.1/16")
	require.NoError(t, addr.SetIPv6FromCompact(mustEncodeV6Prefix(t, oldPrefix)))

	updateAddrCalled := false
	mock := &MockWGIface{
		AddressFunc: func() wgaddr.Address { return addr },
		UpdateAddrFunc: func(a wgaddr.Address) error {
			updateAddrCalled = true
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx:          ctx,
		clientCtx:    ctx,
		clientCancel: cancel,
		config:       &EngineConfig{WgAddr: addr},
		wgInterface:  mock,
		syncMsgMux:   &sync.Mutex{},
	}

	conf := &mgmtProto.PeerConfig{
		Address:   addr.String(),
		AddressV6: mustEncodeV6Prefix(t, newPrefix),
	}
	reset, err := e.reconcileIPv6(conf)
	require.NoError(t, err)
	assert.True(t, reset, "v6 prefix length change must request a reset")
	assert.False(t, updateAddrCalled, "v6 prefix length change must NOT touch the interface")
}

func TestReconcileIPv6_ValueChanged_RequestsReset(t *testing.T) {
	// v6 was X, now Y. The netstack backend can't safely swap an existing
	// address in place — fall back to the engine recreate path.
	oldPrefix := netip.MustParsePrefix("fd00::1/64")
	newPrefix := netip.MustParsePrefix("fd00::2/64")

	addr := wgaddr.MustParseWGAddress("100.64.0.1/16")
	require.NoError(t, addr.SetIPv6FromCompact(mustEncodeV6Prefix(t, oldPrefix)))

	updateAddrCalled := false
	mock := &MockWGIface{
		AddressFunc: func() wgaddr.Address { return addr },
		UpdateAddrFunc: func(a wgaddr.Address) error {
			updateAddrCalled = true
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx:          ctx,
		clientCtx:    ctx,
		clientCancel: cancel,
		config:       &EngineConfig{WgAddr: addr},
		wgInterface:  mock,
		syncMsgMux:   &sync.Mutex{},
	}

	conf := &mgmtProto.PeerConfig{
		Address:   addr.String(),
		AddressV6: mustEncodeV6Prefix(t, newPrefix),
	}
	reset, err := e.reconcileIPv6(conf)
	require.NoError(t, err)
	assert.True(t, reset, "v6 value change must request a reset")
	assert.False(t, updateAddrCalled,
		"v6 value change must NOT call UpdateAddr — caller will recreate the interface")
}

func TestReconcileIPv6_InvalidBytes_ReturnsError(t *testing.T) {
	// Corrupt PeerConfig.AddressV6 must not crash the engine and must not
	// trigger a spurious reset.
	v4 := wgaddr.MustParseWGAddress("100.64.0.1/16")
	e, _, applied := reconcileIPv6Fixture(t, v4)

	conf := &mgmtProto.PeerConfig{
		Address:   v4.String(),
		AddressV6: []byte{0x00}, // truncated, definitely not a valid prefix
	}
	reset, err := e.reconcileIPv6(conf)
	require.Error(t, err, "malformed v6 bytes must surface an error")
	assert.False(t, reset, "decode error must NOT request a reset")
	assert.False(t, applied.HasIPv6(), "decode error must NOT touch the interface")
}

func TestReconcileIPv6_UpdateAddrError_DoesNotPropagateReset(t *testing.T) {
	// If WGIface.UpdateAddr fails (e.g. OS-side assignment error on a
	// kernel device), reconcileIPv6 returns the error to the caller for
	// logging — but it must NOT request a reset. The whole point of the
	// fix is to AVOID the reset cascade on v6 transitions.
	v4 := wgaddr.MustParseWGAddress("100.64.0.1/16")
	mock := &MockWGIface{
		AddressFunc:    func() wgaddr.Address { return v4 },
		UpdateAddrFunc: func(_ wgaddr.Address) error { return errors.New("os refused address") },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx:          ctx,
		clientCtx:    ctx,
		clientCancel: cancel,
		config:       &EngineConfig{WgAddr: v4},
		wgInterface:  mock,
		syncMsgMux:   &sync.Mutex{},
	}

	v6Prefix := netip.MustParsePrefix("fd00::1/64")
	conf := &mgmtProto.PeerConfig{
		Address:   v4.String(),
		AddressV6: mustEncodeV6Prefix(t, v6Prefix),
	}
	reset, err := e.reconcileIPv6(conf)
	require.Error(t, err, "UpdateAddr failure must surface")
	assert.False(t, reset, "UpdateAddr failure must NOT request a reset")
}

func TestUpdateConfig_V6FirstAssignment_DoesNotResetEngine(t *testing.T) {
	// The integration check: updateConfig must not return ErrResetConnection
	// when the only change between current state and the new PeerConfig is
	// "v6 added". Pre-fix this returned ErrResetConnection, tearing down
	// every listener bound on the engine's netstack.
	v4 := wgaddr.MustParseWGAddress("100.64.0.1/16")
	mock := &MockWGIface{
		AddressFunc:        func() wgaddr.Address { return v4 },
		UpdateAddrFunc:     func(_ wgaddr.Address) error { return nil },
		IsUserspaceBindFunc: func() bool { return true },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx:            ctx,
		clientCtx:      ctx,
		clientCancel:   cancel,
		config:         &EngineConfig{WgAddr: v4, WgPort: 51820},
		wgInterface:    mock,
		syncMsgMux:     &sync.Mutex{},
		statusRecorder: peer.NewRecorder("https://mgm.test"),
	}

	v6Prefix := netip.MustParsePrefix("fd00::1/64")
	conf := &mgmtProto.PeerConfig{
		Address:   v4.String(),
		AddressV6: mustEncodeV6Prefix(t, v6Prefix),
	}

	err := e.updateConfig(conf)
	assert.NoError(t, err,
		"updateConfig MUST NOT return ErrResetConnection when v6 is added for the first time — that's the bug fix")
	assert.NotErrorIs(t, err, ErrResetConnection)

	require.True(t, e.config.WgAddr.HasIPv6(), "engine config must record the assigned v6 after updateConfig")
	assert.Equal(t, v6Prefix.Addr(), e.config.WgAddr.IPv6)
}
