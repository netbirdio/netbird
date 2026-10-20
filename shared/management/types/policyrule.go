package types

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// PolicyTrafficActionType action type for the firewall
type PolicyTrafficActionType string

// PolicyRuleProtocolType type of traffic
type PolicyRuleProtocolType string

const (
	// PolicyTrafficActionAccept indicates that the traffic is accepted
	PolicyTrafficActionAccept = PolicyTrafficActionType("accept")
	// PolicyTrafficActionDrop indicates that the traffic is dropped
	PolicyTrafficActionDrop = PolicyTrafficActionType("drop")
)

const (
	// PolicyRuleProtocolALL type of traffic
	PolicyRuleProtocolALL = PolicyRuleProtocolType("all")
	// PolicyRuleProtocolTCP type of traffic
	PolicyRuleProtocolTCP = PolicyRuleProtocolType("tcp")
	// PolicyRuleProtocolUDP type of traffic
	PolicyRuleProtocolUDP = PolicyRuleProtocolType("udp")
	// PolicyRuleProtocolICMP type of traffic
	PolicyRuleProtocolICMP = PolicyRuleProtocolType("icmp")
	// PolicyRuleProtocolNetbirdSSH type of traffic
	PolicyRuleProtocolNetbirdSSH = PolicyRuleProtocolType("netbird-ssh")
)

// RulePortRange represents a range of ports for a firewall rule.
type RulePortRange struct {
	Start uint16
	End   uint16
}

func (r *RulePortRange) ToProto() *proto.PortInfo {
	return &proto.PortInfo{
		PortSelection: &proto.PortInfo_Range_{
			Range: &proto.PortInfo_Range{
				Start: uint32(r.Start),
				End:   uint32(r.End),
			},
		},
	}
}

func (r *RulePortRange) Equal(other *RulePortRange) bool {
	return r.Start == other.Start && r.End == other.End
}

func ParseRuleString(rule string) (PolicyRuleProtocolType, RulePortRange, error) {
	rule = strings.TrimSpace(strings.ToLower(rule))
	if rule == "all" {
		return PolicyRuleProtocolALL, RulePortRange{}, nil
	}
	if rule == "icmp" {
		return PolicyRuleProtocolICMP, RulePortRange{}, nil
	}

	split := strings.Split(rule, "/")
	if len(split) != 2 {
		return "", RulePortRange{}, errors.New("invalid rule format: expected protocol/port or protocol/port-range")
	}

	protoStr := strings.TrimSpace(split[0])
	portStr := strings.TrimSpace(split[1])

	var protocol PolicyRuleProtocolType
	switch protoStr {
	case "tcp":
		protocol = PolicyRuleProtocolTCP
	case "udp":
		protocol = PolicyRuleProtocolUDP
	case "icmp":
		return "", RulePortRange{}, errors.New("icmp does not accept ports; use 'icmp' without '/…'")
	case "netbird-ssh":
		return PolicyRuleProtocolNetbirdSSH, RulePortRange{Start: nativeSSHPortNumber, End: nativeSSHPortNumber}, nil
	default:
		return "", RulePortRange{}, fmt.Errorf("invalid protocol: %q", protoStr)
	}

	portRange, err := parsePortRange(portStr)
	if err != nil {
		return "", RulePortRange{}, err
	}

	return protocol, portRange, nil
}

func parsePortRange(portStr string) (RulePortRange, error) {
	if strings.Contains(portStr, "-") {
		rangeParts := strings.Split(portStr, "-")
		if len(rangeParts) != 2 {
			return RulePortRange{}, fmt.Errorf("invalid port range %q", portStr)
		}
		start, err := parsePort(strings.TrimSpace(rangeParts[0]))
		if err != nil {
			return RulePortRange{}, err
		}
		end, err := parsePort(strings.TrimSpace(rangeParts[1]))
		if err != nil {
			return RulePortRange{}, err
		}
		if start > end {
			return RulePortRange{}, fmt.Errorf("invalid port range: start %d > end %d", start, end)
		}
		return RulePortRange{Start: uint16(start), End: uint16(end)}, nil
	}

	p, err := parsePort(portStr)
	if err != nil {
		return RulePortRange{}, err
	}

	return RulePortRange{Start: uint16(p), End: uint16(p)}, nil
}

func parsePort(portStr string) (int, error) {

	if portStr == "" {
		return 0, errors.New("empty port")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port out of range (1–65535): %d", p)
	}
	return p, nil
}
