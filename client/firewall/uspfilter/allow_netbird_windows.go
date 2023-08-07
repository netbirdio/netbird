package uspfilter

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"inet.af/wf"
)

const (
	netbirdTrafficWeight = 12
)

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	session, err := wf.New(&wf.Options{
		Name:        "Netbird",
		Description: "Netbird dynamic session",
		Dynamic:     true,
	})
	if err != nil {
		return err
	}

	providerID, err := addNetbirdProvider(session)
	if err != nil {
		return err
	}
	m.providerID = providerID

	sublayerID, err := addNetbirdFilterSublayer(session)
	if err != nil {
		return err
	}
	m.sublayerID = sublayerID

	return nil
}

func (m *Manager) allowNetbird() error {
	return m.permitWgInterface()
}

func (m *Manager) permitWgInterface() error {
	luid, err := m.getWgInterfaceLUID()
	if err != nil {
		return err
	}

	conditions := []*wf.Match{
		{
			Field: wf.FieldIPLocalInterface,
			Op:    wf.MatchTypeEqual,
			Value: uint64(luid),
		},
	}

	layers := []wf.LayerID{
		wf.LayerALEAuthRecvAcceptV4,
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthRecvAcceptV6,
		wf.LayerALEAuthConnectV6,
	}

	for _, layer := range layers {
		if err := m.addRule(layer, conditions); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) addRule(layer wf.LayerID, conditions []*wf.Match) error {
	id, err := windows.GenerateGUID()
	if err != nil {
		return err
	}

	r := &wf.Rule{
		Name:       ruleName(m.wgIface.Name(), layer),
		ID:         wf.RuleID(id),
		Provider:   m.providerID,
		Sublayer:   m.sublayerID,
		Layer:      layer,
		Weight:     netbirdTrafficWeight,
		Conditions: conditions,
		Action:     wf.ActionPermit,
	}

	return m.session.AddRule(r)
}

// getWgInterfaceLUID retrieves the tunnel interface locally unique identifier (LUID)
// from globally unique identifier (GUID) of the Manager's wireguard interface.
func (m *Manager) getWgInterfaceLUID() (winipcfg.LUID, error) {
	guidString, err := m.wgIface.GetInterfaceGUIDString()
	if err != nil {
		return 0, err
	}

	guid, err := windows.GUIDFromString(guidString)
	if err != nil {
		return 0, fmt.Errorf("invalid GUID %q: %v", guidString, err)
	}

	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return luid, fmt.Errorf("no interface with GUID %q: %v", guid, err)
	}

	return luid, nil
}

func ruleName(ifaceName string, l wf.LayerID) string {
	switch l {
	case wf.LayerALEAuthConnectV4:
		return fmt.Sprintf("Permit outbound IPv4 traffic on %s", ifaceName)
	case wf.LayerALEAuthConnectV6:
		return fmt.Sprintf("Permit outbound IPv6 traffic on %s", ifaceName)
	case wf.LayerALEAuthRecvAcceptV4:
		return fmt.Sprintf("Permit inbound IPv4 traffic on %s", ifaceName)
	case wf.LayerALEAuthRecvAcceptV6:
		return fmt.Sprintf("Permit inbound IPv6 traffic on %s", ifaceName)
	}
	return ""
}

func addNetbirdProvider(session *wf.Session) (wf.ProviderID, error) {
	var providerID wf.ProviderID

	guid, err := windows.GenerateGUID()
	if err != nil {
		return providerID, err
	}
	providerID = wf.ProviderID(guid)

	err = session.AddProvider(&wf.Provider{
		ID:          providerID,
		Name:        "Netbird",
		Description: "Netbird provider",
	})
	if err != nil {
		return providerID, err
	}

	return providerID, nil
}

func addNetbirdFilterSublayer(session *wf.Session) (wf.SublayerID, error) {
	var sublayerID wf.SublayerID
	guid, err := windows.GenerateGUID()
	if err != nil {
		return sublayerID, err
	}
	sublayerID = wf.SublayerID(guid)

	err = session.AddSublayer(&wf.Sublayer{
		ID:          sublayerID,
		Name:        "Netbird filters",
		Description: "Permissive and blocking filters",
		Weight:      0,
	})
	if err != nil {
		return sublayerID, err
	}

	return sublayerID, nil
}
