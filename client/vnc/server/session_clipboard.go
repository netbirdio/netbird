//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// clipboardPoll periodically checks the server-side clipboard and sends
// changes to the VNC client. Only runs during active sessions.
func (s *session) clipboardPoll(done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastClip string
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			text := s.injector.GetClipboard()
			if len(text) > maxCutTextBytes {
				text = text[:maxCutTextBytes]
			}
			if text == "" || text == lastClip {
				continue
			}
			lastClip = text
			s.encMu.RLock()
			ext := s.clientSupportsExtClipboard
			s.encMu.RUnlock()
			if ext {
				if err := s.writeExtClipMessage(buildExtClipNotify(extClipFormatText)); err != nil {
					s.log.Debugf("send ext clipboard notify: %v", err)
					return
				}
			} else if err := s.sendServerCutText(text); err != nil {
				s.log.Debugf("send clipboard to client: %v", err)
				return
			}
		}
	}
}

func (s *session) handleCutText() error {
	var header [7]byte // 3 padding + 4 length
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read CutText header: %w", err)
	}
	rawLen := int32(binary.BigEndian.Uint32(header[3:7]))
	if rawLen < 0 {
		// Negative length signals ExtendedClipboard; absolute value is the
		// payload size. Guard against MinInt32 overflow before negating.
		if rawLen == -2147483648 {
			return fmt.Errorf("ext clipboard payload too large")
		}
		return s.handleExtCutText(uint32(-rawLen))
	}
	length := uint32(rawLen)
	if length > maxCutTextBytes {
		return fmt.Errorf("cut text too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read CutText payload: %w", err)
	}
	s.injector.SetClipboard(latin1ToUTF8(buf))
	return nil
}

// drainBytes consumes and discards n bytes from the connection. Used to
// skip the payload of a malformed clipboard message after we've decided
// not to honour it, so the next message stays aligned.
func (s *session) drainBytes(n uint32) error {
	if n == 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, s.conn, int64(n)); err != nil {
		return fmt.Errorf("drain %d bytes: %w", n, err)
	}
	return nil
}

// latin1ToUTF8 converts an RFB ClientCutText payload (ISO 8859-1 per
// RFC 6143 §7.5.6) into a UTF-8 string. Bytes 0x80..0xFF map to the
// matching U+0080..U+00FF code points; passing them through Go's
// `string([]byte)` instead would produce invalid UTF-8 that downstream
// clipboard backends mangle.
func latin1ToUTF8(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes)
}

// utf8ToLatin1 converts a UTF-8 string into the Latin-1 byte sequence
// required by legacy ServerCutText (RFC 6143 §7.6.4). Runes outside
// U+0000..U+00FF are not representable in Latin-1; we substitute '?' so the
// peer still receives a coherent message instead of a truncated or
// silently mojibake'd payload. ExtendedClipboard clients take a separate
// path that preserves full UTF-8.
func utf8ToLatin1(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			out = append(out, '?')
			continue
		}
		out = append(out, byte(r))
	}
	return out
}

// handleExtCutText parses an ExtendedClipboard message (any of Caps,
// Notify, Request, Peek, Provide) carried as a negative-length CutText.
// Unknown actions, oversized payloads, and formats we don't handle
// (RTF/HTML/DIB/Files) are logged and dropped instead of aborting the
// session: a malformed clipboard message must never cost the user their
// VNC connection. Read errors on the socket itself still propagate.
func (s *session) handleExtCutText(payloadLen uint32) error {
	if payloadLen < 4 {
		s.log.Debugf("ext clipboard payload too short: %d", payloadLen)
		return s.drainBytes(payloadLen)
	}
	if payloadLen > extClipMaxPayload {
		s.log.Debugf("ext clipboard payload too large: %d", payloadLen)
		return s.drainBytes(payloadLen)
	}
	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read ext clipboard payload: %w", err)
	}
	flags := binary.BigEndian.Uint32(buf[0:4])
	action := flags & extClipActionMask
	formats := flags & extClipFormatMask
	rest := buf[4:]

	// A Caps message sets the Caps bit alongside one bit per action the
	// peer supports, so the action byte is multi-bit. Detect it first; the
	// remaining actions are single-bit and are dispatched after.
	if action&extClipActionCaps != 0 {
		// Client max sizes are informational for us today: we only emit
		// text and already cap it at extClipMaxText.
		return nil
	}

	switch action {
	case extClipActionRequest:
		if formats&extClipFormatText != 0 {
			return s.sendExtClipProvideText()
		}
		return nil
	case extClipActionPeek:
		return s.writeExtClipMessage(buildExtClipNotify(extClipFormatText))
	case extClipActionNotify:
		if formats&extClipFormatText != 0 {
			return s.writeExtClipMessage(buildExtClipRequest(extClipFormatText))
		}
		return nil
	case extClipActionProvide:
		s.handleExtClipProvide(flags, rest)
		return nil
	default:
		s.log.Debugf("unknown ext clipboard action 0x%x", action)
		return nil
	}
}

// handleExtClipProvide decodes a Provide payload and pushes the recovered
// text into the host clipboard. Decode errors and unsupported formats (RTF,
// HTML, etc.) are logged and dropped so a malformed message doesn't tear
// down the session.
func (s *session) handleExtClipProvide(flags uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	text, err := parseExtClipProvideText(flags, payload)
	if err != nil {
		s.log.Debugf("parse ext clipboard provide: %v", err)
		return
	}
	if text != "" {
		s.injector.SetClipboard(text)
	}
}

// sendExtClipProvideText answers an inbound Request(text) with the current
// host clipboard contents, capped to extClipMaxText.
func (s *session) sendExtClipProvideText() error {
	text := s.injector.GetClipboard()
	if len(text) > extClipMaxText {
		text = text[:extClipMaxText]
	}
	payload, err := buildExtClipProvideText(text)
	if err != nil {
		return fmt.Errorf("build provide: %w", err)
	}
	return s.writeExtClipMessage(payload)
}

// writeExtClipMessage frames an ExtendedClipboard payload as a ServerCutText
// message with a negative length, then writes it under writeMu.
func (s *session) writeExtClipMessage(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	buf := make([]byte, 8+len(payload))
	buf[0] = serverCutText
	// buf[1:4] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(-int32(len(payload))))
	copy(buf[8:], payload)

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}

// handleTypeText handles the NetBird-specific PasteAndType message that
// pushes host clipboard content as synthesized keystrokes, used to reach
// secure desktops where the clipboard is isolated. Wire format mirrors
// CutText: 3-byte padding + 4-byte length + text bytes.
func (s *session) handleTypeText() error {
	var header [7]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read TypeText header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[3:7])
	if length > maxCutTextBytes {
		return fmt.Errorf("type text too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read TypeText payload: %w", err)
	}
	s.injector.TypeText(string(buf))
	return nil
}

// sendServerCutText sends clipboard text from the server to the legacy
// (non-ExtendedClipboard) client. The wire encoding is Latin-1; runes that
// fall outside U+0000..U+00FF are best-effort replaced with '?' since the
// peer cannot represent them.
func (s *session) sendServerCutText(text string) error {
	data := utf8ToLatin1(text)
	buf := make([]byte, 8+len(data))
	buf[0] = serverCutText
	// buf[1:4] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}
