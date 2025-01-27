package server

import (
	"context"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) ForwardingRules(context.Context, *proto.EmptyRequest) (*proto.ForwardingRulesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rules := s.statusRecorder.ForwardingRules()
	responseRules := make([]*proto.ForwardingRule, 0, len(rules))
	for _, rule := range rules {
		respRule := &proto.ForwardingRule{
			Protocol:           string(rule.Protocol),
			DestinationPort:    portToProto(rule.DestinationPort),
			TranslatedAddress:  rule.TranslatedAddress.String(),
			TranslatedHostname: s.hostNameByTranslateAddress(rule.TranslatedAddress.String()),
			TranslatedPort:     portToProto(rule.TranslatedPort),
		}
		responseRules = append(responseRules, respRule)

	}

	return &proto.ForwardingRulesResponse{Rules: responseRules}, nil
}

func (s *Server) hostNameByTranslateAddress(ip string) string {
	hostName, ok := s.statusRecorder.PeerByIP(ip)
	if !ok {
		return ip
	}

	return hostName
}

func portToProto(port firewall.Port) *proto.PortInfo {
	var portInfo proto.PortInfo

	if !port.IsRange {
		portInfo.PortSelection = &proto.PortInfo_Port{Port: uint32(port.Values[0])}
	} else {
		portInfo.PortSelection = &proto.PortInfo_Range_{
			Range: &proto.PortInfo_Range{
				Start: uint32(port.Values[0]),
				End:   uint32(port.Values[1]),
			},
		}
	}
	return &portInfo
}
