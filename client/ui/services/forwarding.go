//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// PortRange is a port range; both ends are inclusive.
type PortRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// PortInfo holds exactly one of Port or Range (the daemon's oneof).
type PortInfo struct {
	Port  *uint32    `json:"port,omitempty"`
	Range *PortRange `json:"range,omitempty"`
}

// ForwardingRule is one entry from the daemon's reverse-proxy table.
type ForwardingRule struct {
	Protocol           string   `json:"protocol"`
	DestinationPort    PortInfo `json:"destinationPort"`
	TranslatedAddress  string   `json:"translatedAddress"`
	TranslatedHostname string   `json:"translatedHostname"`
	TranslatedPort     PortInfo `json:"translatedPort"`
}

// Forwarding groups the daemon RPCs that surface exposed/forwarded services.
type Forwarding struct {
	conn DaemonConn
}

func NewForwarding(conn DaemonConn) *Forwarding {
	return &Forwarding{conn: conn}
}

func (s *Forwarding) List(ctx context.Context) ([]ForwardingRule, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := cli.ForwardingRules(ctx, &proto.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]ForwardingRule, 0, len(resp.GetRules()))
	for _, r := range resp.GetRules() {
		out = append(out, forwardingRuleFromProto(r))
	}
	return out, nil
}

func forwardingRuleFromProto(r *proto.ForwardingRule) ForwardingRule {
	return ForwardingRule{
		Protocol:           r.GetProtocol(),
		DestinationPort:    portInfoFromProto(r.GetDestinationPort()),
		TranslatedAddress:  r.GetTranslatedAddress(),
		TranslatedHostname: r.GetTranslatedHostname(),
		TranslatedPort:     portInfoFromProto(r.GetTranslatedPort()),
	}
}

func portInfoFromProto(p *proto.PortInfo) PortInfo {
	if p == nil {
		return PortInfo{}
	}
	switch sel := p.GetPortSelection().(type) {
	case *proto.PortInfo_Port:
		port := sel.Port
		return PortInfo{Port: &port}
	case *proto.PortInfo_Range_:
		r := sel.Range
		if r == nil {
			return PortInfo{}
		}
		return PortInfo{Range: &PortRange{Start: r.GetStart(), End: r.GetEnd()}}
	}
	return PortInfo{}
}
