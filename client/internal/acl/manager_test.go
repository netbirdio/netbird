package acl

import (
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	"github.com/netbirdio/netbird/client/internal/netflow"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
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
	network := netip.MustParsePrefix("172.0.0.1/32")

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
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
	network := netip.MustParsePrefix("172.0.0.1/32")

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
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

func TestPortInfoEmpty(t *testing.T) {
	tests := []struct {
		name     string
		portInfo *mgmProto.PortInfo
		expected bool
	}{
		{
			name:     "nil PortInfo should be empty",
			portInfo: nil,
			expected: true,
		},
		{
			name: "PortInfo with zero port should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Port{
					Port: 0,
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with valid port should not be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Port{
					Port: 80,
				},
			},
			expected: false,
		},
		{
			name: "PortInfo with nil range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: nil,
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with zero start range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 0,
						End:   100,
					},
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with zero end range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 80,
						End:   0,
					},
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with valid range should not be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 8080,
						End:   8090,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := portInfoEmpty(tt.portInfo)
			assert.Equal(t, tt.expected, result)
		})
	}
}
