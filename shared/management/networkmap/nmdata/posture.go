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

// Check is the slim twin of posture.Check. It is sealed: only the check types
// in this package implement it.
type Check interface {
	check(peer *Peer) (bool, error)
}

// Passes reports whether the peer satisfies every check in this bundle. It
// mirrors the server posture path: a check returning (false, _) — including on
// an evaluation error — fails the bundle.
func (pc *PostureChecks) Passes(peer *Peer) bool {
	return PassesChecks(pc.GetChecks(), peer)
}

// PassesChecks is Passes over an already built check set, for callers that
// evaluate many peers against the same bundle.
func PassesChecks(checks []Check, peer *Peer) bool {
	for _, c := range checks {
		valid, _ := c.check(peer)
		if !valid {
			return false
		}
	}
	return true
}

// PostureVerdictChanged reports whether any check in the bundles gives a different
// verdict for newPeer than for oldPeer. Checks are replayed one by one, so a change
// that moves a field but stays on the same side of a threshold does not count. An
// evaluation error is a deny, like in PassesChecks.
func PostureVerdictChanged(checks []*PostureChecks, oldPeer, newPeer *Peer) bool {
	for _, pc := range checks {
		for _, c := range pc.GetChecks() {
			single := []Check{c}
			if PassesChecks(single, oldPeer) != PassesChecks(single, newPeer) {
				return true
			}
		}
	}
	return false
}

// GetChecks returns the initialized checks in the same order as posture.Checks.GetChecks.
func (pc *PostureChecks) GetChecks() []Check {
	var checks []Check
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
