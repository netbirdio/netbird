//go:build !js && !ios && !android

package server

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

// ExtendedClipboard is an RFB community extension (pseudo-encoding
// 0xC0A1E5CE) that replaces legacy CutText with a Caps/Notify/Request/
// Provide/Peek handshake. Wins versus legacy CutText:
//   - UTF-8 text format (legacy is Latin-1).
//   - Pull-based: a Notify announces "I have new content", the peer fetches
//     via Request only when it actually needs the data. Saves bandwidth on
//     high-latency transports versus pushing every change.
//   - zlib-compressed payloads.
//   - Caps negotiation so each side knows the other's per-format max size.
//
// The extension reuses message opcodes 3 (ServerCutText) and 6 (ClientCutText)
// and signals "extended" by encoding the length field as a negative int32;
// the absolute value is the payload size in bytes. The first 4 bytes of
// payload are a flags word: top byte is the action, low 16 bits are the
// format mask.
const pseudoEncExtendedClipboard = -1063131698 // 0xC0A1E5CE as int32

const (
	extClipActionCaps    uint32 = 0x01000000
	extClipActionRequest uint32 = 0x02000000
	extClipActionPeek    uint32 = 0x04000000
	extClipActionNotify  uint32 = 0x08000000
	extClipActionProvide uint32 = 0x10000000
	extClipActionMask    uint32 = 0x1F000000

	extClipFormatText  uint32 = 0x00000001
	extClipFormatRTF   uint32 = 0x00000002
	extClipFormatHTML  uint32 = 0x00000004
	extClipFormatDIB   uint32 = 0x00000008
	extClipFormatFiles uint32 = 0x00000010
	extClipFormatMask  uint32 = 0x0000FFFF

	// extClipMaxText caps our accepted text payload. Mirrors the legacy
	// maxCutTextBytes (1 MiB); advertised in Caps and enforced on Provide.
	extClipMaxText = maxCutTextBytes

	// extClipMaxPayload bounds the raw on-wire payload we will read for an
	// extended CutText message. Includes flags header, length prefixes, NUL,
	// and zlib framing overhead on top of the text body.
	extClipMaxPayload = extClipMaxText + 1024
)

// buildExtClipCaps emits the Caps payload. The flags word advertises every
// action we support in the high byte (Caps + Request + Peek + Notify +
// Provide) and every format we accept in the low 16 bits. Clients use
// these action bits to decide whether to auto-Request on Notify; without
// Request in our Caps a conforming client silently drops our Notify
// messages. After the flags word we emit one uint32 max size per format
// bit set, in ascending bit order.
func buildExtClipCaps() []byte {
	flags := extClipActionCaps | extClipActionRequest | extClipActionPeek |
		extClipActionNotify | extClipActionProvide | extClipFormatText
	payload := make([]byte, 4+4)
	binary.BigEndian.PutUint32(payload[0:4], flags)
	binary.BigEndian.PutUint32(payload[4:8], uint32(extClipMaxText))
	return payload
}

// buildExtClipNotify emits a Notify announcing that we have new clipboard
// content available in the given format mask. No data is shipped; the peer
// pulls via Request when it actually needs to paste.
func buildExtClipNotify(formats uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, extClipActionNotify|formats)
	return payload
}

// buildExtClipRequest emits a Request asking the peer to send Provide for
// the given format mask. Sent in response to an inbound Notify.
func buildExtClipRequest(formats uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, extClipActionRequest|formats)
	return payload
}

// buildExtClipProvideText emits a Provide carrying UTF-8 text. The inner
// stream (4-byte length including the trailing NUL, then UTF-8 bytes, then
// NUL) is zlib-compressed; each Provide uses an independent zlib context
// per the extension spec. Rejects oversized input so a caller bug can't
// produce a payload larger than the size advertised in our Caps.
func buildExtClipProvideText(text string) ([]byte, error) {
	if len(text)+1 > extClipMaxText {
		return nil, fmt.Errorf("clipboard text exceeds extClipMaxText (%d > %d)", len(text)+1, extClipMaxText)
	}
	body := make([]byte, 0, 4+len(text)+1)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(text)+1))
	body = append(body, lenBuf[:]...)
	body = append(body, text...)
	body = append(body, 0)

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		return nil, fmt.Errorf("zlib write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zlib close: %w", err)
	}

	payload := make([]byte, 4+compressed.Len())
	binary.BigEndian.PutUint32(payload[0:4], extClipActionProvide|extClipFormatText)
	copy(payload[4:], compressed.Bytes())
	return payload, nil
}

// parseExtClipProvideText decompresses a Provide payload (the bytes after
// the 4-byte flags header) and returns the UTF-8 text record if the text
// format bit is set. Records for other formats are skipped. The trailing
// NUL byte the spec appends to text records is stripped.
func parseExtClipProvideText(flags uint32, payload []byte) (string, error) {
	zr, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("zlib reader: %w", err)
	}
	defer zr.Close()

	limited := io.LimitReader(zr, int64(extClipMaxText)+16)
	var text string
	for bit := uint32(1); bit <= extClipFormatFiles; bit <<= 1 {
		if flags&bit == 0 {
			continue
		}
		var sizeBuf [4]byte
		if _, err := io.ReadFull(limited, sizeBuf[:]); err != nil {
			if bit == extClipFormatText && err == io.EOF {
				return "", nil
			}
			return "", fmt.Errorf("read record size: %w", err)
		}
		size := binary.BigEndian.Uint32(sizeBuf[:])
		if size > uint32(extClipMaxText) {
			return "", fmt.Errorf("record too large: %d", size)
		}
		rec := make([]byte, size)
		if _, err := io.ReadFull(limited, rec); err != nil {
			return "", fmt.Errorf("read record: %w", err)
		}
		if bit == extClipFormatText {
			if len(rec) > 0 && rec[len(rec)-1] == 0 {
				rec = rec[:len(rec)-1]
			}
			text = string(rec)
		}
	}
	return text, nil
}
