// Package pcp implements the Port Control Protocol (RFC 6887).
//
// # Implemented Features
//
//   - ANNOUNCE opcode: Discovers PCP server support
//   - MAP opcode: Creates/deletes port mappings (IPv4 NAT) and firewall pinholes (IPv6)
//   - Dual-stack: Simultaneous IPv4 and IPv6 support via separate clients
//   - Nonce validation: Prevents response spoofing
//   - Epoch tracking: Detects server restarts per Section 8.5
//   - RFC-compliant retry timing: 3s initial, exponential backoff to 1024s max (Section 8.1.1)
//
// # Not Implemented
//
//   - PEER opcode: For outbound peer connections (not needed for inbound NAT traversal)
//   - THIRD_PARTY option: For managing mappings on behalf of other devices
//   - PREFER_FAILURE option: Requires exact external port or fail (IPv4 NAT only, not needed for IPv6 pinholing)
//   - FILTER option: To restrict remote peer addresses
//
// These optional features are omitted because the primary use case is simple
// port forwarding for WireGuard, which only requires MAP with default behavior.
package pcp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	// Version is the PCP protocol version (RFC 6887).
	Version = 2

	// Port is the standard PCP server port.
	Port = 5351

	// DefaultLifetime is the default requested mapping lifetime in seconds.
	DefaultLifetime = 7200 // 2 hours

	// Header sizes
	headerSize     = 24
	mapPayloadSize = 36
	mapRequestSize = headerSize + mapPayloadSize // 60 bytes
)

// Opcodes
const (
	OpAnnounce = 0
	OpMap      = 1
	OpPeer     = 2
	OpReply    = 0x80 // OR'd with opcode in responses
)

// Protocol numbers for MAP requests
const (
	ProtoUDP = 17
	ProtoTCP = 6
)

// Result codes (RFC 6887 Section 7.4)
const (
	ResultSuccess              = 0
	ResultUnsuppVersion        = 1
	ResultNotAuthorized        = 2
	ResultMalformedRequest     = 3
	ResultUnsuppOpcode         = 4
	ResultUnsuppOption         = 5
	ResultMalformedOption      = 6
	ResultNetworkFailure       = 7
	ResultNoResources          = 8
	ResultUnsuppProtocol       = 9
	ResultUserExQuota          = 10
	ResultCannotProvideExt     = 11
	ResultAddressMismatch      = 12
	ResultExcessiveRemotePeers = 13
)

// ResultCodeString returns a human-readable string for a result code.
func ResultCodeString(code uint8) string {
	switch code {
	case ResultSuccess:
		return "SUCCESS"
	case ResultUnsuppVersion:
		return "UNSUPP_VERSION"
	case ResultNotAuthorized:
		return "NOT_AUTHORIZED"
	case ResultMalformedRequest:
		return "MALFORMED_REQUEST"
	case ResultUnsuppOpcode:
		return "UNSUPP_OPCODE"
	case ResultUnsuppOption:
		return "UNSUPP_OPTION"
	case ResultMalformedOption:
		return "MALFORMED_OPTION"
	case ResultNetworkFailure:
		return "NETWORK_FAILURE"
	case ResultNoResources:
		return "NO_RESOURCES"
	case ResultUnsuppProtocol:
		return "UNSUPP_PROTOCOL"
	case ResultUserExQuota:
		return "USER_EX_QUOTA"
	case ResultCannotProvideExt:
		return "CANNOT_PROVIDE_EXTERNAL"
	case ResultAddressMismatch:
		return "ADDRESS_MISMATCH"
	case ResultExcessiveRemotePeers:
		return "EXCESSIVE_REMOTE_PEERS"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", code)
	}
}

// Response represents a parsed PCP response header.
type Response struct {
	Version    uint8
	Opcode     uint8
	ResultCode uint8
	Lifetime   uint32
	Epoch      uint32
}

// MapResponse contains the full response to a MAP request.
type MapResponse struct {
	Response
	Nonce        [12]byte
	Protocol     uint8
	InternalPort uint16
	ExternalPort uint16
	ExternalIP   netip.Addr
}

// addrTo16 converts an address to its 16-byte IPv4-mapped IPv6 representation.
func addrTo16(addr netip.Addr) [16]byte {
	if addr.Is4() {
		return netip.AddrFrom4(addr.As4()).As16()
	}
	return addr.As16()
}

// addrFrom16 extracts an address from a 16-byte representation, unmapping IPv4.
func addrFrom16(b [16]byte) netip.Addr {
	return netip.AddrFrom16(b).Unmap()
}

// buildAnnounceRequest creates a PCP ANNOUNCE request packet.
func buildAnnounceRequest(clientIP netip.Addr) []byte {
	req := make([]byte, headerSize)
	req[0] = Version
	req[1] = OpAnnounce
	mapped := addrTo16(clientIP)
	copy(req[8:24], mapped[:])
	return req
}

// buildMapRequest creates a PCP MAP request packet.
func buildMapRequest(clientIP netip.Addr, nonce [12]byte, protocol uint8, internalPort, suggestedExtPort uint16, suggestedExtIP netip.Addr, lifetime uint32) []byte {
	req := make([]byte, mapRequestSize)

	// Header
	req[0] = Version
	req[1] = OpMap
	binary.BigEndian.PutUint32(req[4:8], lifetime)
	mapped := addrTo16(clientIP)
	copy(req[8:24], mapped[:])

	// MAP payload
	copy(req[24:36], nonce[:])
	req[36] = protocol
	binary.BigEndian.PutUint16(req[40:42], internalPort)
	binary.BigEndian.PutUint16(req[42:44], suggestedExtPort)
	if suggestedExtIP.IsValid() {
		extMapped := addrTo16(suggestedExtIP)
		copy(req[44:60], extMapped[:])
	}

	return req
}

// parseResponse parses the common PCP response header.
func parseResponse(data []byte) (*Response, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	resp := &Response{
		Version:    data[0],
		Opcode:     data[1],
		ResultCode: data[3], // Byte 2 is reserved, byte 3 is result code (RFC 6887 §7.2)
		Lifetime:   binary.BigEndian.Uint32(data[4:8]),
		Epoch:      binary.BigEndian.Uint32(data[8:12]),
	}

	if resp.Version != Version {
		return nil, fmt.Errorf("unsupported PCP version: %d", resp.Version)
	}

	if resp.Opcode&OpReply == 0 {
		return nil, fmt.Errorf("response missing reply bit: opcode=0x%02x", resp.Opcode)
	}

	return resp, nil
}

// parseMapResponse parses a complete MAP response.
func parseMapResponse(data []byte) (*MapResponse, error) {
	if len(data) < mapRequestSize {
		return nil, fmt.Errorf("MAP response too short: %d bytes", len(data))
	}

	resp, err := parseResponse(data)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	mapResp := &MapResponse{
		Response:     *resp,
		Protocol:     data[36],
		InternalPort: binary.BigEndian.Uint16(data[40:42]),
		ExternalPort: binary.BigEndian.Uint16(data[42:44]),
		ExternalIP:   addrFrom16([16]byte(data[44:60])),
	}
	copy(mapResp.Nonce[:], data[24:36])

	return mapResp, nil
}
