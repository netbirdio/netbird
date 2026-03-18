package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// TLS record header is 5 bytes: ContentType(1) + Version(2) + Length(2).
	tlsRecordHeaderLen = 5
	// TLS handshake type for ClientHello.
	handshakeTypeClientHello = 1
	// TLS ContentType for handshake messages.
	contentTypeHandshake = 22
	// SNI extension type (RFC 6066).
	extensionServerName = 0
	// SNI host name type.
	sniHostNameType = 0
	// maxClientHelloLen caps the ClientHello size we're willing to buffer.
	maxClientHelloLen = 16384
	// maxSNILen is the maximum valid DNS hostname length per RFC 1035.
	maxSNILen = 253
)

// PeekClientHello reads the TLS ClientHello from conn, extracts the SNI
// server name, and returns a wrapped connection that replays the peeked
// bytes transparently. If the data is not a valid TLS ClientHello or
// contains no SNI extension, sni is empty and err is nil.
//
// ECH/ESNI: When the client uses Encrypted Client Hello (TLS 1.3), the
// real server name is encrypted inside the encrypted_client_hello
// extension. This parser only reads the cleartext server_name extension
// (type 0x0000), so ECH connections return sni="" and are routed through
// the fallback path (or HTTP channel), which is the correct behavior
// for a transparent proxy that does not terminate TLS.
func PeekClientHello(conn net.Conn) (sni string, wrapped net.Conn, err error) {
	// Read the 5-byte TLS record header into a small stack-friendly buffer.
	var header [tlsRecordHeaderLen]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", nil, fmt.Errorf("read TLS record header: %w", err)
	}

	if header[0] != contentTypeHandshake {
		return "", newPeekedConn(conn, header[:]), nil
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen == 0 || recordLen > maxClientHelloLen {
		return "", newPeekedConn(conn, header[:]), nil
	}

	// Single allocation for header + payload. The peekedConn takes
	// ownership of this buffer, so no further copies are needed.
	buf := make([]byte, tlsRecordHeaderLen+recordLen)
	copy(buf, header[:])

	n, err := io.ReadFull(conn, buf[tlsRecordHeaderLen:])
	if err != nil {
		return "", newPeekedConn(conn, buf[:tlsRecordHeaderLen+n]), fmt.Errorf("read TLS handshake payload: %w", err)
	}

	sni = extractSNI(buf[tlsRecordHeaderLen:])
	return sni, newPeekedConn(conn, buf), nil
}

// extractSNI parses a TLS handshake payload to find the SNI extension.
// Returns empty string if the payload is not a ClientHello or has no SNI.
func extractSNI(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	if payload[0] != handshakeTypeClientHello {
		return ""
	}

	// Handshake length (3 bytes, big-endian).
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen > len(payload)-4 {
		return ""
	}

	return parseSNIFromClientHello(payload[4 : 4+handshakeLen])
}

// parseSNIFromClientHello walks the ClientHello message fields to reach
// the extensions block and extract the server_name extension value.
func parseSNIFromClientHello(msg []byte) string {
	// ClientHello layout:
	//   ProtocolVersion(2) + Random(32) = 34 bytes minimum before session_id
	if len(msg) < 34 {
		return ""
	}

	pos := 34

	// Session ID (variable, 1 byte length prefix).
	if pos >= len(msg) {
		return ""
	}
	sessionIDLen := int(msg[pos])
	pos++
	pos += sessionIDLen

	// Cipher suites (variable, 2 byte length prefix).
	if pos+2 > len(msg) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(msg[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	// Compression methods (variable, 1 byte length prefix).
	if pos >= len(msg) {
		return ""
	}
	compMethodsLen := int(msg[pos])
	pos++
	pos += compMethodsLen

	// Extensions (variable, 2 byte length prefix).
	if pos+2 > len(msg) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(msg[pos : pos+2]))
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(msg) {
		return ""
	}

	return findSNIExtension(msg[pos:extensionsEnd])
}

// findSNIExtension iterates over TLS extensions and returns the host
// name from the server_name extension, if present.
func findSNIExtension(extensions []byte) string {
	pos := 0
	for pos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > len(extensions) {
			return ""
		}

		if extType == extensionServerName {
			return parseSNIExtensionData(extensions[pos : pos+extLen])
		}
		pos += extLen
	}
	return ""
}

// parseSNIExtensionData parses the ServerNameList structure inside an
// SNI extension to extract the host name.
func parseSNIExtensionData(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen > len(data)-2 {
		return ""
	}

	list := data[2 : 2+listLen]
	pos := 0
	for pos+3 <= len(list) {
		nameType := list[pos]
		nameLen := int(binary.BigEndian.Uint16(list[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > len(list) {
			return ""
		}

		if nameType == sniHostNameType {
			name := list[pos : pos+nameLen]
			if nameLen > maxSNILen || bytes.ContainsRune(name, 0) {
				return ""
			}
			return string(name)
		}
		pos += nameLen
	}
	return ""
}
