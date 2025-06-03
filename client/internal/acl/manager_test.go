package acl

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	"github.com/netbirdio/netbird/client/internal/netflow"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

func TestDefaultManager(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	ip, network, err := net.ParseCIDR("172.0.0.1/32")
	require.NoError(t, err)

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      ip,
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false)
	require.NoError(t, err)
	defer func() {
		err = fw.Close(nil)
		require.NoError(t, err)
	}()

	acl := NewDefaultManager(fw)

	t.Run("apply firewall rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap, false)

		if fw.IsStateful() {
			assert.Equal(t, 0, len(acl.peerRulesPairs))
		} else {
			assert.Equal(t, 2, len(acl.peerRulesPairs))
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		existedPairs := map[string]struct{}{}
		for id := range acl.peerRulesPairs {
			existedPairs[id.ID()] = struct{}{}
		}

		// remove first rule
		networkMap.FirewallRules = networkMap.FirewallRules[1:]
		networkMap.FirewallRules = append(
			networkMap.FirewallRules,
			&mgmProto.FirewallRule{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_ICMP,
			},
		)

		acl.ApplyFiltering(networkMap, false)

		expectedRules := 2
		if fw.IsStateful() {
			expectedRules = 1 // only the inbound rule
		}

		assert.Equal(t, expectedRules, len(acl.peerRulesPairs))

		// check that old rule was removed
		previousCount := 0
		for id := range acl.peerRulesPairs {
			if _, ok := existedPairs[id.ID()]; ok {
				previousCount++
			}
		}

		expectedPreviousCount := 0
		if !fw.IsStateful() {
			expectedPreviousCount = 1
		}
		assert.Equal(t, expectedPreviousCount, previousCount)
	})

	t.Run("handle default rules", func(t *testing.T) {
		networkMap.FirewallRules = networkMap.FirewallRules[:0]

		networkMap.FirewallRulesIsEmpty = true
		acl.ApplyFiltering(networkMap, false)
		assert.Equal(t, 0, len(acl.peerRulesPairs))

		networkMap.FirewallRulesIsEmpty = false
		acl.ApplyFiltering(networkMap, false)

		expectedRules := 1
		if fw.IsStateful() {
			expectedRules = 1 // only inbound allow-all rule
		}
		assert.Equal(t, expectedRules, len(acl.peerRulesPairs))
	})
}

func TestDefaultManagerStateless(t *testing.T) {
	// stateless currently only in userspace, so we have to disable kernel
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv("NB_DISABLE_CONNTRACK", "true")

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	ip, network, err := net.ParseCIDR("172.0.0.1/32")
	require.NoError(t, err)

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      ip,
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false)
	require.NoError(t, err)
	defer func() {
		err = fw.Close(nil)
		require.NoError(t, err)
	}()

	acl := NewDefaultManager(fw)

	t.Run("stateless firewall creates outbound rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap, false)

		// In stateless mode, we should have both inbound and outbound rules
		assert.False(t, fw.IsStateful())
		assert.Equal(t, 2, len(acl.peerRulesPairs))
	})
}

func TestDefaultManagerSquashRules(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
			{AllowedIps: []string{"10.93.0.4"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
		},
	}

	manager := &DefaultManager{}
	rules, _ := manager.squashAcceptRules(networkMap)
	assert.Equal(t, 2, len(rules))

	r := rules[0]
	assert.Equal(t, "0.0.0.0", r.PeerIP)
	assert.Equal(t, mgmProto.RuleDirection_IN, r.Direction)
	assert.Equal(t, mgmProto.RuleProtocol_ALL, r.Protocol)
	assert.Equal(t, mgmProto.RuleAction_ACCEPT, r.Action)

	r = rules[1]
	assert.Equal(t, "0.0.0.0", r.PeerIP)
	assert.Equal(t, mgmProto.RuleDirection_OUT, r.Direction)
	assert.Equal(t, mgmProto.RuleProtocol_ALL, r.Protocol)
	assert.Equal(t, mgmProto.RuleAction_ACCEPT, r.Action)
}

func TestDefaultManagerSquashRulesNoAffect(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
			{AllowedIps: []string{"10.93.0.4"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_ALL,
			},
			{
				PeerIP:    "10.93.0.4",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
			},
		},
	}

	manager := &DefaultManager{}
	rules, _ := manager.squashAcceptRules(networkMap)
	assert.Equal(t, len(networkMap.FirewallRules), len(rules))
}

func TestDefaultManagerEnableSSHRules(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		PeerConfig: &mgmProto.PeerConfig{
			SshConfig: &mgmProto.SSHConfig{
				SshEnabled: true,
			},
		},
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{AllowedIps: []string{"10.93.0.1"}},
			{AllowedIps: []string{"10.93.0.2"}},
			{AllowedIps: []string{"10.93.0.3"}},
		},
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	ip, network, err := net.ParseCIDR("172.0.0.1/32")
	require.NoError(t, err)

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      ip,
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false)
	require.NoError(t, err)
	defer func() {
		err = fw.Close(nil)
		require.NoError(t, err)
	}()

	acl := NewDefaultManager(fw)

	acl.ApplyFiltering(networkMap, false)

	expectedRules := 3
	if fw.IsStateful() {
		expectedRules = 3 // 2 inbound rules + SSH rule
	}
	assert.Equal(t, expectedRules, len(acl.peerRulesPairs))
}
