package inspect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/netbirdio/netbird/shared/management/domain"
)

// QUIC version constants
const (
	quicV1Version uint32 = 0x00000001
	quicV2Version uint32 = 0x6b3343cf
)

// quicV1Salt is the initial salt for QUIC v1 (RFC 9001 Section 5.2).
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// quicV2Salt is the initial salt for QUIC v2 (RFC 9369).
var quicV2Salt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
}

// ExtractQUICSNI extracts the SNI from a QUIC Initial packet.
// The Initial packet's encryption uses well-known keys derived from the
// Destination Connection ID, so any observer can decrypt it (by design).
func ExtractQUICSNI(data []byte) (domain.Domain, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("packet too short")
	}

	// Check for QUIC Long Header (form bit set)
	if data[0]&0x80 == 0 {
		return "", fmt.Errorf("not a QUIC long header packet")
	}

	// Version
	version := binary.BigEndian.Uint32(data[1:5])

	var salt []byte
	var initialLabel, keyLabel, ivLabel, hpLabel string

	switch version {
	case quicV1Version:
		salt = quicV1Salt
		initialLabel = "client in"
		keyLabel = "quic key"
		ivLabel = "quic iv"
		hpLabel = "quic hp"
	case quicV2Version:
		salt = quicV2Salt
		initialLabel = "client in"
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
		hpLabel = "quicv2 hp"
	default:
		return "", fmt.Errorf("unsupported QUIC version: 0x%08x", version)
	}

	// Parse Long Header
	if len(data) < 6 {
		return "", fmt.Errorf("packet too short for DCID length")
	}
	dcidLen := int(data[5])
	if len(data) < 6+dcidLen+1 {
		return "", fmt.Errorf("packet too short for DCID")
	}
	dcid := data[6 : 6+dcidLen]

	scidLenOff := 6 + dcidLen
	scidLen := int(data[scidLenOff])
	tokenLenOff := scidLenOff + 1 + scidLen

	if tokenLenOff >= len(data) {
		return "", fmt.Errorf("packet too short for token length")
	}

	// Token length is a variable-length integer
	tokenLen, tokenLenSize, err := readVarInt(data[tokenLenOff:])
	if err != nil {
		return "", fmt.Errorf("read token length: %w", err)
	}

	payloadLenOff := tokenLenOff + tokenLenSize + int(tokenLen)
	if payloadLenOff >= len(data) {
		return "", fmt.Errorf("packet too short for payload length")
	}

	// Payload length is a variable-length integer
	payloadLen, payloadLenSize, err := readVarInt(data[payloadLenOff:])
	if err != nil {
		return "", fmt.Errorf("read payload length: %w", err)
	}

	pnOffset := payloadLenOff + payloadLenSize
	if pnOffset+4 > len(data) {
		return "", fmt.Errorf("packet too short for packet number")
	}

	// Derive initial keys
	clientKey, clientIV, clientHP, err := deriveInitialKeys(dcid, salt, initialLabel, keyLabel, ivLabel, hpLabel)
	if err != nil {
		return "", fmt.Errorf("derive initial keys: %w", err)
	}

	// Remove header protection
	sampleOffset := pnOffset + 4 // sample starts 4 bytes after pn offset
	if sampleOffset+16 > len(data) {
		return "", fmt.Errorf("packet too short for HP sample")
	}
	sample := data[sampleOffset : sampleOffset+16]

	hpBlock, err := aes.NewCipher(clientHP)
	if err != nil {
		return "", fmt.Errorf("create HP cipher: %w", err)
	}

	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, sample)

	// Unmask header byte
	header := make([]byte, len(data))
	copy(header, data)
	header[0] ^= mask[0] & 0x0f // Long header: low 4 bits

	// Determine packet number length
	pnLen := int(header[0]&0x03) + 1

	// Unmask packet number
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
	}

	// Reconstruct packet number
	var pn uint32
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint32(header[pnOffset+i])
	}

	// Build nonce
	nonce := make([]byte, len(clientIV))
	copy(nonce, clientIV)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	// Decrypt payload
	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create AEAD: %w", err)
	}

	encryptedPayload := header[pnOffset+pnLen : pnOffset+int(payloadLen)]
	aad := header[:pnOffset+pnLen]

	plaintext, err := aead.Open(nil, nonce, encryptedPayload, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt QUIC payload: %w", err)
	}

	// Parse CRYPTO frames to extract ClientHello
	clientHello, err := extractCryptoFrames(plaintext)
	if err != nil {
		return "", fmt.Errorf("extract CRYPTO frames: %w", err)
	}

	info, err := parseHelloBody(clientHello)
	return info.SNI, err
}

// deriveInitialKeys derives the client's initial encryption keys from the DCID.
func deriveInitialKeys(dcid, salt []byte, initialLabel, keyLabel, ivLabel, hpLabel string) (key, iv, hp []byte, err error) {
	// initial_secret = HKDF-Extract(salt, DCID)
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)

	// client_initial_secret = HKDF-Expand-Label(initial_secret, initialLabel, "", 32)
	clientSecret, err := hkdfExpandLabel(initialSecret, initialLabel, nil, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive client secret: %w", err)
	}

	// client_key = HKDF-Expand-Label(client_secret, keyLabel, "", 16)
	key, err = hkdfExpandLabel(clientSecret, keyLabel, nil, 16)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive key: %w", err)
	}

	// client_iv = HKDF-Expand-Label(client_secret, ivLabel, "", 12)
	iv, err = hkdfExpandLabel(clientSecret, ivLabel, nil, 12)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive IV: %w", err)
	}

	// client_hp = HKDF-Expand-Label(client_secret, hpLabel, "", 16)
	hp, err = hkdfExpandLabel(clientSecret, hpLabel, nil, 16)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive HP key: %w", err)
	}

	return key, iv, hp, nil
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// HkdfLabel = struct {
	//   uint16 length;
	//   opaque label<7..255> = "tls13 " + Label;
	//   opaque context<0..255> = Context;
	// }
	fullLabel := "tls13 " + label

	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	if len(context) > 0 {
		copy(hkdfLabel[4+len(fullLabel):], context)
	}

	expander := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(expander, out); err != nil {
		return nil, err
	}
	return out, nil
}

// maxCryptoFrameSize limits total CRYPTO frame data to prevent memory exhaustion.
const maxCryptoFrameSize = 64 * 1024

// extractCryptoFrames reassembles CRYPTO frame data from QUIC frames.
func extractCryptoFrames(frames []byte) ([]byte, error) {
	var result []byte
	pos := 0

	for pos < len(frames) {
		frameType := frames[pos]

		switch {
		case frameType == 0x00:
			// PADDING frame
			pos++

		case frameType == 0x06:
			// CRYPTO frame
			pos++

			offset, n, err := readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read crypto offset: %w", err)
			}
			pos += n
			_ = offset // We assume ordered, offset 0 for Initial

			dataLen, n, err := readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read crypto data length: %w", err)
			}
			pos += n

			end := pos + int(dataLen)
			if end > len(frames) {
				return nil, fmt.Errorf("CRYPTO frame data truncated")
			}

			result = append(result, frames[pos:end]...)
			if len(result) > maxCryptoFrameSize {
				return nil, fmt.Errorf("CRYPTO frame data exceeds %d bytes", maxCryptoFrameSize)
			}
			pos = end

		case frameType == 0x01:
			// PING frame
			pos++

		case frameType == 0x02 || frameType == 0x03:
			// ACK frame - skip
			pos++
			// Largest Acknowledged
			_, n, err := readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read ACK: %w", err)
			}
			pos += n
			// ACK Delay
			_, n, err = readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read ACK delay: %w", err)
			}
			pos += n
			// ACK Range Count
			rangeCount, n, err := readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read ACK range count: %w", err)
			}
			pos += n
			// First ACK Range
			_, n, err = readVarInt(frames[pos:])
			if err != nil {
				return nil, fmt.Errorf("read first ACK range: %w", err)
			}
			pos += n
			// Additional ranges
			for i := uint64(0); i < rangeCount; i++ {
				_, n, err = readVarInt(frames[pos:])
				if err != nil {
					return nil, fmt.Errorf("read ACK gap: %w", err)
				}
				pos += n
				_, n, err = readVarInt(frames[pos:])
				if err != nil {
					return nil, fmt.Errorf("read ACK range: %w", err)
				}
				pos += n
			}
			// ECN counts for type 0x03
			if frameType == 0x03 {
				for range 3 {
					_, n, err = readVarInt(frames[pos:])
					if err != nil {
						return nil, fmt.Errorf("read ECN count: %w", err)
					}
					pos += n
				}
			}

		default:
			// Unknown frame type, stop parsing
			if len(result) > 0 {
				return result, nil
			}
			return nil, fmt.Errorf("unknown QUIC frame type: 0x%02x at offset %d", frameType, pos)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no CRYPTO frames found")
	}

	return result, nil
}

// readVarInt reads a QUIC variable-length integer.
// Returns (value, bytes consumed, error).
func readVarInt(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data for varint")
	}

	prefix := data[0] >> 6
	length := 1 << prefix

	if len(data) < length {
		return 0, 0, fmt.Errorf("varint truncated: need %d, have %d", length, len(data))
	}

	var val uint64
	switch length {
	case 1:
		val = uint64(data[0] & 0x3f)
	case 2:
		val = uint64(binary.BigEndian.Uint16(data[:2])) & 0x3fff
	case 4:
		val = uint64(binary.BigEndian.Uint32(data[:4])) & 0x3fffffff
	case 8:
		val = binary.BigEndian.Uint64(data[:8]) & 0x3fffffffffffffff
	}

	return val, length, nil
}
