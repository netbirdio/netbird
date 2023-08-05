package uspfilter

import (
	"golang.org/x/sys/windows"

	"inet.af/wf"
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
	return nil
}

func (m *Manager) permitWt0Interface() error {
	// TODO: find the interface luid
	luid := uint64(0)

	conditions := []*wf.Match{
		{
			Field: wf.FieldIPLocalInterface,
			Op:    wf.MatchTypeEqual,
			Value: luid,
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
		Name:       ruleName(layer),
		ID:         wf.RuleID(id),
		Provider:   m.providerID,
		Sublayer:   m.sublayerID,
		Layer:      layer,
		Weight:     12, // TODO: verify the traffic weight for netbird
		Conditions: conditions,
		Action:     wf.ActionPermit,
	}

	return m.session.AddRule(r)
}

func ruleName(l wf.LayerID) string {
	switch l {
	case wf.LayerALEAuthConnectV4:
		return "Permit outbound IPv4 traffic on wt0"
	case wf.LayerALEAuthConnectV6:
		return "Permit outbound IPv6 traffic on wt0"
	case wf.LayerALEAuthRecvAcceptV4:
		return "Permit inbound IPv4 traffic on wt0"
	case wf.LayerALEAuthRecvAcceptV6:
		return "Permit inbound IPv6 traffic on wt0"
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
