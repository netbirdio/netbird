package types

import (
	"errors"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type NetworkRouter struct {
	ID         string `gorm:"primaryKey"`
	NetworkID  string `gorm:"index"`
	AccountID  string `gorm:"index"`
	Peer       string
	PeerGroups []string `gorm:"serializer:json"`
	Masquerade bool
	Metric     int
	Enabled    bool
	Inspection *InspectionConfig `gorm:"serializer:json"`
}

// InspectionConfig holds traffic inspection settings for a routing peer.
// L7 inspection rules are stored separately as ProxyRule entities.
type InspectionConfig struct {
	Enabled       bool            `json:"enabled"`
	Mode          string          `json:"mode"`           // "builtin" or "external"
	ExternalURL   string          `json:"external_url"`
	DefaultAction string          `json:"default_action"` // "allow", "block", "inspect"
	RedirectPorts []int           `json:"redirect_ports"`
	ICAP          *InspectionICAP `json:"icap,omitempty"`
	CACertPEM     string          `json:"ca_cert_pem,omitempty"`
	CAKeyPEM      string          `json:"ca_key_pem,omitempty"`
	ListenPort    int             `json:"listen_port"`
}

// InspectionICAP holds ICAP service configuration.
type InspectionICAP struct {
	ReqModURL      string `json:"reqmod_url"`
	RespModURL     string `json:"respmod_url"`
	MaxConnections int    `json:"max_connections"`
}

func NewNetworkRouter(accountID string, networkID string, peer string, peerGroups []string, masquerade bool, metric int, enabled bool) (*NetworkRouter, error) {
	if peer != "" && len(peerGroups) > 0 {
		return nil, errors.New("peer and peerGroups cannot be set at the same time")
	}

	return &NetworkRouter{
		ID:         xid.New().String(),
		AccountID:  accountID,
		NetworkID:  networkID,
		Peer:       peer,
		PeerGroups: peerGroups,
		Masquerade: masquerade,
		Metric:     metric,
		Enabled:    enabled,
	}, nil
}

func (n *NetworkRouter) ToAPIResponse() *api.NetworkRouter {
	resp := &api.NetworkRouter{
		Id:         n.ID,
		Peer:       &n.Peer,
		PeerGroups: &n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}

	if n.Inspection != nil {
		resp.Inspection = inspectionToAPI(n.Inspection)
	}

	return resp
}

func (n *NetworkRouter) FromAPIRequest(req *api.NetworkRouterRequest) {
	if req.Peer != nil {
		n.Peer = *req.Peer
	}

	if req.PeerGroups != nil {
		n.PeerGroups = *req.PeerGroups
	}

	n.Masquerade = req.Masquerade
	n.Metric = req.Metric
	n.Enabled = req.Enabled
	n.Inspection = inspectionFromAPI(req.Inspection)
}

func (n *NetworkRouter) Copy() *NetworkRouter {
	c := &NetworkRouter{
		ID:         n.ID,
		NetworkID:  n.NetworkID,
		AccountID:  n.AccountID,
		Peer:       n.Peer,
		PeerGroups: n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
	if n.Inspection != nil {
		insp := *n.Inspection
		c.Inspection = &insp
	}
	return c
}

func inspectionToAPI(c *InspectionConfig) *api.RouterInspectionConfig {
	if c == nil {
		return nil
	}

	mode := api.RouterInspectionConfigMode(c.Mode)
	defaultAction := api.RouterInspectionConfigDefaultAction(c.DefaultAction)

	resp := &api.RouterInspectionConfig{
		Enabled:       c.Enabled,
		Mode:          &mode,
		DefaultAction: &defaultAction,
	}

	if c.ExternalURL != "" {
		resp.ExternalUrl = &c.ExternalURL
	}

	if len(c.RedirectPorts) > 0 {
		resp.RedirectPorts = &c.RedirectPorts
	}

	if c.CACertPEM != "" {
		resp.CaCertPem = &c.CACertPEM
	}
	if c.CAKeyPEM != "" {
		resp.CaKeyPem = &c.CAKeyPEM
	}

	if c.ICAP != nil {
		icap := api.InspectionICAPConfig{}
		if c.ICAP.ReqModURL != "" {
			icap.ReqmodUrl = &c.ICAP.ReqModURL
		}
		if c.ICAP.RespModURL != "" {
			icap.RespmodUrl = &c.ICAP.RespModURL
		}
		if c.ICAP.MaxConnections > 0 {
			icap.MaxConnections = &c.ICAP.MaxConnections
		}
		resp.Icap = &icap
	}

	return resp
}

func inspectionFromAPI(c *api.RouterInspectionConfig) *InspectionConfig {
	if c == nil {
		return nil
	}

	insp := &InspectionConfig{
		Enabled: c.Enabled,
	}

	if c.Mode != nil {
		insp.Mode = string(*c.Mode)
	}
	if c.DefaultAction != nil {
		insp.DefaultAction = string(*c.DefaultAction)
	}
	if c.ExternalUrl != nil {
		insp.ExternalURL = *c.ExternalUrl
	}
	if c.RedirectPorts != nil {
		insp.RedirectPorts = *c.RedirectPorts
	}
	if c.CaCertPem != nil {
		insp.CACertPEM = *c.CaCertPem
	}
	if c.CaKeyPem != nil {
		insp.CAKeyPEM = *c.CaKeyPem
	}

	if c.Icap != nil {
		insp.ICAP = &InspectionICAP{}
		if c.Icap.ReqmodUrl != nil {
			insp.ICAP.ReqModURL = *c.Icap.ReqmodUrl
		}
		if c.Icap.RespmodUrl != nil {
			insp.ICAP.RespModURL = *c.Icap.RespmodUrl
		}
		if c.Icap.MaxConnections != nil {
			insp.ICAP.MaxConnections = *c.Icap.MaxConnections
		}
	}

	return insp
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func (n *NetworkRouter) EventMeta(network *types.Network) map[string]any {
	return map[string]any{"network_name": network.Name, "network_id": network.ID, "peer": n.Peer, "peer_groups": n.PeerGroups}
}
