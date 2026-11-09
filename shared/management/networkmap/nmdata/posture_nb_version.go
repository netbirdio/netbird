package nmdata

import (
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
)

// NBVersionCheck is the slim twin of posture.NBVersionCheck.
type NBVersionCheck struct {
	MinVersion string

	constraintOnce sync.Once
	constraint     version.Constraints
	constraintErr  error
}

func (n *NBVersionCheck) check(peer *Peer) (bool, error) {
	peerNBVer, err := version.NewVersion(sanitizeVersion(peer.Meta.WtVersion))
	if err != nil {
		return false, err
	}

	n.constraintOnce.Do(func() {
		n.constraint, n.constraintErr = version.NewConstraint(">= " + sanitizeVersion(n.MinVersion))
	})
	if n.constraintErr != nil {
		return false, n.constraintErr
	}

	return n.constraint.Check(peerNBVer), nil
}

func sanitizeVersion(v string) string {
	parts := strings.Split(v, "-")
	return parts[0]
}
