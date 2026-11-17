package posture

import (
	"context"
	"fmt"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbversion "github.com/netbirdio/netbird/version"
)

type NBVersionCheck struct {
	MinVersion string
}

var _ Check = (*NBVersionCheck)(nil)

func (n *NBVersionCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	meetsMin, err := nbversion.MeetsMinVersion(n.MinVersion, peer.Meta.WtVersion)
	if err != nil {
		return false, err
	}

	if meetsMin {
		return true, nil
	}

	return false, nil
}

func (n *NBVersionCheck) Name() string {
	return NBVersionCheckName
}

func (n *NBVersionCheck) Validate() error {
	if n.MinVersion == "" {
		return fmt.Errorf("%s minimum version shouldn't be empty", n.Name())
	}
	if !isVersionValid(n.MinVersion) {
		return fmt.Errorf("%s version: %s is not valid", n.Name(), n.MinVersion)
	}
	return nil
}
