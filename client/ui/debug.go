//go:build !(linux && 386)

package main

import (
	"fmt"
	"path/filepath"

	"fyne.io/fyne/v2"
	"github.com/skratchdot/open-golang/open"

	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
)

func (s *serviceClient) createAndOpenDebugBundle() error {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return fmt.Errorf("get client: %v", err)
	}

	statusResp, err := conn.Status(s.ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		return fmt.Errorf("failed to get status: %v", err)
	}

	overview := nbstatus.ConvertToStatusOutputOverview(statusResp, true, "", nil, nil, nil)
	statusOutput := nbstatus.ParseToFullDetailSummary(overview)

	resp, err := conn.DebugBundle(s.ctx, &proto.DebugBundleRequest{
		Anonymize:  true,
		Status:     statusOutput,
		SystemInfo: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create debug bundle: %v", err)
	}

	bundleDir := filepath.Dir(resp.GetPath())
	if err := open.Start(bundleDir); err != nil {
		return fmt.Errorf("failed to open debug bundle directory: %v", err)
	}

	s.app.SendNotification(fyne.NewNotification(
		"Debug Bundle",
		fmt.Sprintf("Debug bundle created at %s. Administrator privileges are required to access it.", resp.GetPath()),
	))

	return nil
}
