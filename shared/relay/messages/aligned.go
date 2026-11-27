package messages

import (
	"encoding/binary"
	"fmt"
)

const (
	// ExtTypeAlignedHeartbeat is the type of the aligned heartbeat entry in the extension area
	// of the Auth envelope and of the AuthResponse envelope. Type 1 is the peer auth proof.
	ExtTypeAlignedHeartbeat byte = 2

	sizeOfExtHeader      = 1 + 2
	offsetExtEntryLength = 1
	sizeOfAlignedPeriod  = 2
)

// AppendAlignedHeartbeatEntry appends the aligned heartbeat entry to an extension area: type,
// value length uint16 big endian, then the period in seconds, uint16 big endian. A client puts
// the period it asks for in its Auth envelope, the relay the period it accepted in its
// AuthResponse envelope.
func AppendAlignedHeartbeatEntry(ext []byte, periodSeconds uint16) []byte {
	ext = append(ext, ExtTypeAlignedHeartbeat)
	ext = binary.BigEndian.AppendUint16(ext, sizeOfAlignedPeriod)
	return binary.BigEndian.AppendUint16(ext, periodSeconds)
}

// AlignedHeartbeatEntry returns the period of the first aligned heartbeat entry in an
// extension area, skipping entries of other types. Value bytes after the period are ignored,
// so a later release can add fields there. ok is false without an entry and for a zero period.
// An error means a malformed area or entry; the caller then stays stock. The period is
// returned raw; the caller clamps it.
func AlignedHeartbeatEntry(ext []byte) (periodSeconds uint16, ok bool, err error) {
	for len(ext) > 0 {
		if len(ext) < sizeOfExtHeader {
			return 0, false, fmt.Errorf("extension entry header of %d bytes: %w", len(ext), ErrInvalidMessageLength)
		}
		typ := ext[0]
		n := int(binary.BigEndian.Uint16(ext[offsetExtEntryLength:sizeOfExtHeader]))
		if len(ext) < sizeOfExtHeader+n {
			return 0, false, fmt.Errorf("extension entry of %d bytes beyond the area: %w", n, ErrInvalidMessageLength)
		}
		value := ext[sizeOfExtHeader : sizeOfExtHeader+n]
		ext = ext[sizeOfExtHeader+n:]
		if typ != ExtTypeAlignedHeartbeat {
			continue
		}
		if n < sizeOfAlignedPeriod {
			return 0, false, fmt.Errorf("aligned heartbeat entry of %d bytes: %w", n, ErrInvalidMessageLength)
		}
		periodSeconds = binary.BigEndian.Uint16(value)
		return periodSeconds, periodSeconds != 0, nil
	}
	return 0, false, nil
}
