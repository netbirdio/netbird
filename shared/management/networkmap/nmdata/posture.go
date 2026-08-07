package nmdata

const (
	checkActionAllow = "allow"
	checkActionDeny  = "deny"
)

// PostureChecks is the slim twin of posture.Checks.
type PostureChecks struct {
	ID     string
	Checks ChecksDefinition
}

// ChecksDefinition is the slim twin of posture.ChecksDefinition.
type ChecksDefinition struct {
	NBVersionCheck        *NBVersionCheck
	OSVersionCheck        *OSVersionCheck
	GeoLocationCheck      *GeoLocationCheck
	PeerNetworkRangeCheck *PeerNetworkRangeCheck
	ProcessCheck          *ProcessCheck
}

type postureCheck interface {
	check(peer *Peer) (bool, error)
}

// Passes reports whether the peer satisfies every check in this bundle. It
// mirrors the server posture path: a check returning (false, _) — including on
// an evaluation error — fails the bundle.
func (pc *PostureChecks) Passes(peer *Peer) bool {
	for _, c := range pc.GetChecks() {
		valid, _ := c.check(peer)
		if !valid {
			return false
		}
	}
	return true
}

// GetChecks returns the initialized checks in the same order as posture.Checks.GetChecks.
func (pc *PostureChecks) GetChecks() []postureCheck {
	var checks []postureCheck
	if pc.Checks.NBVersionCheck != nil {
		checks = append(checks, pc.Checks.NBVersionCheck)
	}
	if pc.Checks.OSVersionCheck != nil {
		checks = append(checks, pc.Checks.OSVersionCheck)
	}
	if pc.Checks.GeoLocationCheck != nil {
		checks = append(checks, pc.Checks.GeoLocationCheck)
	}
	if pc.Checks.PeerNetworkRangeCheck != nil {
		checks = append(checks, pc.Checks.PeerNetworkRangeCheck)
	}
	if pc.Checks.ProcessCheck != nil {
		checks = append(checks, pc.Checks.ProcessCheck)
	}
	return checks
}
