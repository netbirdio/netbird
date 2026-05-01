// Package connectionmode defines the Mode type used to control how a peer
// establishes connections to other peers. Introduced in Phase 1 of the
// connection-mode consolidation (issue #5989) to replace the historical
// pair (NB_FORCE_RELAY, NB_ENABLE_EXPERIMENTAL_LAZY_CONN).
package connectionmode

import (
	"fmt"
	"strings"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Mode is a connection mode for peer-to-peer (or relay-only) connections.
// ModeUnspecified is the zero value and indicates "fall back to the next
// resolution source" (env -> config -> server-pushed -> legacy bool).
type Mode int

const (
	ModeUnspecified Mode = iota
	ModeRelayForced
	ModeP2P
	ModeP2PLazy
	ModeP2PDynamic
	// ModeFollowServer is a client-side sentinel: setting this in the
	// client config explicitly clears any local override so the
	// server-pushed value (or its legacy fallback) is used. It MUST NOT
	// be sent on the wire -- ToProto returns UNSPECIFIED for it.
	ModeFollowServer
)

// String returns the canonical lower-kebab-case name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeRelayForced:
		return "relay-forced"
	case ModeP2P:
		return "p2p"
	case ModeP2PLazy:
		return "p2p-lazy"
	case ModeP2PDynamic:
		return "p2p-dynamic"
	case ModeFollowServer:
		return "follow-server"
	default:
		return ""
	}
}

// ParseString accepts the canonical name (case-insensitive, surrounding
// whitespace tolerated) and returns the corresponding Mode. Empty input
// returns ModeUnspecified with no error. Unknown input returns
// ModeUnspecified with an error.
func ParseString(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ModeUnspecified, nil
	case "relay-forced":
		return ModeRelayForced, nil
	case "p2p":
		return ModeP2P, nil
	case "p2p-lazy":
		return ModeP2PLazy, nil
	case "p2p-dynamic":
		return ModeP2PDynamic, nil
	case "follow-server":
		return ModeFollowServer, nil
	default:
		return ModeUnspecified, fmt.Errorf("unknown connection mode %q", s)
	}
}

// FromProto translates a proto enum value to the internal Mode.
func FromProto(m mgmProto.ConnectionMode) Mode {
	switch m {
	case mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED:
		return ModeRelayForced
	case mgmProto.ConnectionMode_CONNECTION_MODE_P2P:
		return ModeP2P
	case mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY:
		return ModeP2PLazy
	case mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC:
		return ModeP2PDynamic
	default:
		return ModeUnspecified
	}
}

// ToProto translates the internal Mode to a proto enum value.
// ModeFollowServer is a client-side concept and intentionally maps to
// UNSPECIFIED so it never appears on the wire.
func (m Mode) ToProto() mgmProto.ConnectionMode {
	switch m {
	case ModeRelayForced:
		return mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED
	case ModeP2P:
		return mgmProto.ConnectionMode_CONNECTION_MODE_P2P
	case ModeP2PLazy:
		return mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY
	case ModeP2PDynamic:
		return mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC
	default:
		return mgmProto.ConnectionMode_CONNECTION_MODE_UNSPECIFIED
	}
}

// ResolveLegacyLazyBool maps the historical Settings.LazyConnectionEnabled
// boolean to the new Mode. Used when a new client receives an old server's
// PeerConfig (ConnectionMode = UNSPECIFIED) or when the management server
// has no explicit Settings.ConnectionMode set yet.
func ResolveLegacyLazyBool(lazy bool) Mode {
	if lazy {
		return ModeP2PLazy
	}
	return ModeP2P
}

// ToLazyConnectionEnabled is the inverse mapping for backwards-compat.
// Used by toPeerConfig() so old clients (which only know the boolean)
// still get a sensible behaviour.
//
// Note: ModeRelayForced cannot be expressed via the legacy boolean and
// falls back to false. This is a structural compat gap documented in the
// release notes; admins must set NB_FORCE_RELAY=true on old clients
// or upgrade them.
func (m Mode) ToLazyConnectionEnabled() bool {
	return m == ModeP2PLazy
}
