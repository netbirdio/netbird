package net

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// envFwmarkBase overrides the base of the fwmark range. Container network
	// plugins, CNIs and other VPNs claim bits of the mark space for themselves,
	// and a rule of theirs matching one of our bits acts on our traffic, so
	// hosts running such software may need to move the range out of the way.
	envFwmarkBase = "NB_FWMARK_BASE"

	// defaultFwmarkBase is the base of the fwmark range used when the
	// environment does not override it.
	defaultFwmarkBase uint32 = 0x1BD00

	// fwmarkOffsetMask is the part of a mark that identifies the individual mark
	// within the range, so the base occupies everything above it.
	fwmarkOffsetMask uint32 = 0xFF
)

// Offsets of the individual marks within the range.
const (
	offsetControlPlane     uint32 = 0x00
	offsetDataPlaneIn      uint32 = 0x10
	offsetDataPlaneOut     uint32 = 0x11
	offsetRedirected       uint32 = 0x20
	offsetMasquerade       uint32 = 0x21
	offsetMasqueradeReturn uint32 = 0x22
	offsetDataPlaneLower   uint32 = 0x10
	offsetDataPlaneUpper   uint32 = fwmarkOffsetMask
)

var (
	fwmarkBase = loadFwmarkBase()

	// ControlPlaneMark is the fwmark value used to mark packets that should not be routed through the NetBird interface to
	// avoid routing loops.
	// This includes all control plane traffic (mgmt, signal, flows), relay, ICE/stun/turn and everything that is emitted by the wireguard socket.
	// It doesn't collide with the other marks, as the others are used for data plane traffic only.
	ControlPlaneMark = fwmarkBase | offsetControlPlane

	// DataPlaneMarkLower is the lowest value for the data plane range
	DataPlaneMarkLower = fwmarkBase | offsetDataPlaneLower
	// DataPlaneMarkUpper is the highest value for the data plane range
	DataPlaneMarkUpper = fwmarkBase | offsetDataPlaneUpper

	// DataPlaneMarkIn is the mark for inbound data plane traffic.
	DataPlaneMarkIn = fwmarkBase | offsetDataPlaneIn

	// DataPlaneMarkOut is the mark for outbound data plane traffic.
	DataPlaneMarkOut = fwmarkBase | offsetDataPlaneOut

	// PreroutingFwmarkRedirected is applied to packets that were redirected (input -> forward, e.g. by Docker or Podman) for special handling.
	PreroutingFwmarkRedirected = fwmarkBase | offsetRedirected

	// PreroutingFwmarkMasquerade is applied to packets that arrive from the NetBird interface and should be masqueraded.
	PreroutingFwmarkMasquerade = fwmarkBase | offsetMasquerade

	// PreroutingFwmarkMasqueradeReturn is applied to packets that will leave through the NetBird interface and should be masqueraded.
	PreroutingFwmarkMasqueradeReturn = fwmarkBase | offsetMasqueradeReturn
)

// IsDataPlaneMark determines if a fwmark is in the data plane range.
func IsDataPlaneMark(fwmark uint32) bool {
	return fwmark >= DataPlaneMarkLower && fwmark <= DataPlaneMarkUpper
}

func loadFwmarkBase() uint32 {
	val := os.Getenv(envFwmarkBase)
	if val == "" {
		return defaultFwmarkBase
	}

	base, err := parseFwmarkBase(val)
	if err != nil {
		log.Warnf("failed to parse %s=%q, using the default range: %v", envFwmarkBase, val, err)
		return defaultFwmarkBase
	}

	log.Infof("using fwmark range %#x-%#x from %s", base, base|fwmarkOffsetMask, envFwmarkBase)
	return base
}

// parseFwmarkBase reads a mark range base. The low byte of a mark identifies the
// individual mark within the range, so a base has to leave it free.
func parseFwmarkBase(val string) (uint32, error) {
	val = strings.TrimSpace(val)

	base, err := strconv.ParseUint(val, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("not a 32 bit number: %w", err)
	}

	if base == 0 {
		return 0, fmt.Errorf("base must not be zero")
	}

	if uint32(base)&fwmarkOffsetMask != 0 {
		return 0, fmt.Errorf("base %#x must leave the low byte free", base)
	}

	return uint32(base), nil
}
