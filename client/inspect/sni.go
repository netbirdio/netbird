package inspect

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/netbirdio/netbird/shared/management/domain"
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extensionTypeSNI         = 0x0000
	extensionTypeALPN        = 0x0010
	sniTypeHostName          = 0x00

	// maxClientHelloSize is the maximum ClientHello size we'll read.
	// Real-world ClientHellos are typically under 1KB but can reach ~16KB with
	// many extensions (post-quantum key shares, etc.).
	maxClientHelloSize = 16384
)

// ClientHelloInfo holds data extracted from a TLS ClientHello.
type ClientHelloInfo struct {
	SNI  domain.Domain
	ALPN []string
}

// isTLSHandshake reports whether the first byte indicates a TLS handshake record.
func isTLSHandshake(b byte) bool {
	return b == recordTypeHandshake
}

// httpMethods lists the first bytes of valid HTTP method tokens.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST"),
	[]byte("PUT "),
	[]byte("DELE"),
	[]byte("HEAD"),
	[]byte("OPTI"),
	[]byte("PATC"),
	[]byte("CONN"),
	[]byte("TRAC"),
}

// isHTTPMethod reports whether the peeked bytes look like the start of an HTTP request.
func isHTTPMethod(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, m := range httpMethods {
		if b[0] == m[0] && b[1] == m[1] && b[2] == m[2] && b[3] == m[3] {
			return true
		}
	}
	return false
}

// parseClientHello reads a TLS ClientHello from r and returns SNI and ALPN.
func parseClientHello(r io.Reader) (ClientHelloInfo, error) {
	// TLS record header: type(1) + version(2) + length(2)
	var recordHeader [5]byte
	if _, err := io.ReadFull(r, recordHeader[:]); err != nil {
		return ClientHelloInfo{}, fmt.Errorf("read TLS record header: %w", err)
	}

	if recordHeader[0] != recordTypeHandshake {
		return ClientHelloInfo{}, fmt.Errorf("not a TLS handshake record (type=%d)", recordHeader[0])
	}

	recordLen := int(binary.BigEndian.Uint16(recordHeader[3:5]))
	if recordLen < 4 || recordLen > maxClientHelloSize {
		return ClientHelloInfo{}, fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	// Read the full handshake message
	msg := make([]byte, recordLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return ClientHelloInfo{}, fmt.Errorf("read handshake message: %w", err)
	}

	return parseClientHelloMsg(msg)
}

// extractSNI reads a TLS ClientHello from r and returns the SNI hostname.
// Returns empty domain if no SNI extension is present.
func extractSNI(r io.Reader) (domain.Domain, error) {
	info, err := parseClientHello(r)
	return info.SNI, err
}

// extractSNIFromBytes parses SNI from raw bytes that start with the TLS record header.
func extractSNIFromBytes(data []byte) (domain.Domain, error) {
	info, err := parseClientHelloFromBytes(data)
	return info.SNI, err
}

// parseClientHelloFromBytes parses a ClientHello from raw bytes starting with the TLS record header.
func parseClientHelloFromBytes(data []byte) (ClientHelloInfo, error) {
	if len(data) < 5 {
		return ClientHelloInfo{}, fmt.Errorf("data too short for TLS record header")
	}

	if data[0] != recordTypeHandshake {
		return ClientHelloInfo{}, fmt.Errorf("not a TLS handshake record (type=%d)", data[0])
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen < 4 {
		return ClientHelloInfo{}, fmt.Errorf("invalid TLS record length: %d", recordLen)
	}

	end := 5 + recordLen
	if end > len(data) {
		return ClientHelloInfo{}, fmt.Errorf("TLS record truncated: need %d, have %d", end, len(data))
	}

	return parseClientHelloMsg(data[5:end])
}

// parseClientHelloMsg extracts SNI and ALPN from a raw ClientHello handshake message.
// msg starts at the handshake type byte.
func parseClientHelloMsg(msg []byte) (ClientHelloInfo, error) {
	if len(msg) < 4 {
		return ClientHelloInfo{}, fmt.Errorf("handshake message too short")
	}

	if msg[0] != handshakeTypeClientHello {
		return ClientHelloInfo{}, fmt.Errorf("not a ClientHello (type=%d)", msg[0])
	}

	// Handshake header: type(1) + length(3)
	helloLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if helloLen+4 > len(msg) {
		return ClientHelloInfo{}, fmt.Errorf("ClientHello truncated")
	}

	hello := msg[4 : 4+helloLen]
	return parseHelloBody(hello)
}

// parseHelloBody parses the ClientHello body (after handshake header)
// and extracts SNI and ALPN.
func parseHelloBody(hello []byte) (ClientHelloInfo, error) {
	// ClientHello structure:
	// version(2) + random(32) + session_id_len(1) + session_id(var)
	// + cipher_suites_len(2) + cipher_suites(var)
	// + compression_len(1) + compression(var)
	// + extensions_len(2) + extensions(var)

	var info ClientHelloInfo

	if len(hello) < 35 {
		return info, fmt.Errorf("ClientHello body too short")
	}

	pos := 2 + 32 // skip version + random

	// Skip session ID
	if pos >= len(hello) {
		return info, fmt.Errorf("ClientHello truncated at session ID")
	}
	sessionIDLen := int(hello[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(hello) {
		return info, fmt.Errorf("ClientHello truncated at cipher suites")
	}
	cipherLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + cipherLen

	// Skip compression methods
	if pos >= len(hello) {
		return info, fmt.Errorf("ClientHello truncated at compression")
	}
	compLen := int(hello[pos])
	pos += 1 + compLen

	// Extensions
	if pos+2 > len(hello) {
		return info, nil
	}

	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2

	extEnd := pos + extLen
	if extEnd > len(hello) {
		return info, fmt.Errorf("extensions block truncated")
	}

	// Walk extensions looking for SNI and ALPN
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hello[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		pos += 4

		if pos+extDataLen > extEnd {
			return info, fmt.Errorf("extension data truncated")
		}

		switch extType {
		case extensionTypeSNI:
			sni, err := parseSNIExtension(hello[pos : pos+extDataLen])
			if err != nil {
				return info, err
			}
			info.SNI = sni
		case extensionTypeALPN:
			info.ALPN = parseALPNExtension(hello[pos : pos+extDataLen])
		}

		pos += extDataLen
	}

	return info, nil
}

// parseALPNExtension parses the ALPN extension data and returns protocol names.
// ALPN extension: list_length(2) + entries (each: len(1) + protocol_name(var))
func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return nil
	}

	var protocols []string
	pos := 2
	end := 2 + listLen

	for pos < end {
		if pos >= len(data) {
			break
		}
		nameLen := int(data[pos])
		pos++
		if pos+nameLen > end {
			break
		}
		protocols = append(protocols, string(data[pos:pos+nameLen]))
		pos += nameLen
	}

	return protocols
}

// parseSNIExtension parses the SNI extension data and returns the hostname.
func parseSNIExtension(data []byte) (domain.Domain, error) {
	// SNI extension: list_length(2) + entries
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return "", fmt.Errorf("SNI list truncated")
	}

	pos := 2
	end := 2 + listLen

	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > end {
			return "", fmt.Errorf("SNI name truncated")
		}

		if nameType == sniTypeHostName {
			hostname := string(data[pos : pos+nameLen])
			return domain.FromString(hostname)
		}

		pos += nameLen
	}

	return "", nil
}
