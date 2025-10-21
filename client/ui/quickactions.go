//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

// showQuickActionsUI displays a simple window with connect/disconnect controls.
func (s *serviceClient) showQuickActionsUI() {
	s.wQuickActions = s.app.NewWindow("NetBird")
	s.wQuickActions.SetOnClosed(s.cancel)

	statusLabel := widget.NewLabel("Status: Checking...")
	connectBtn := widget.NewButton("Connect", nil)
	disconnectBtn := widget.NewButton("Disconnect", nil)

	updateUI := func() {
		client, err := s.getSrvClient(defaultFailTimeout)
		if err != nil {
			log.Errorf("get service client: %v", err)
			statusLabel.SetText("Status: Error connecting to daemon")
			connectBtn.Disable()
			disconnectBtn.Disable()
			return
		}

		status, err := client.Status(context.Background(), &proto.StatusRequest{})
		if err != nil {
			log.Errorf("get status: %v", err)
			statusLabel.SetText("Status: Error")
			connectBtn.Disable()
			disconnectBtn.Disable()
			return
		}

		if status.Status == peer.StatusConnected.String() {
			statusLabel.SetText("Status: Connected")
			connectBtn.Disable()
			disconnectBtn.Enable()
		} else {
			statusLabel.SetText("Status: Disconnected")
			connectBtn.Enable()
			disconnectBtn.Disable()
		}
	}

	connectBtn.OnTapped = func() {
		connectBtn.Disable()
		statusLabel.SetText("Status: Connecting...")
		go func() {
			if err := s.menuUpClick(); err != nil {
				log.Errorf("connect failed: %v", err)
				statusLabel.SetText(fmt.Sprintf("Status: Error - %v", err))
			}
			updateUI()
		}()
	}

	disconnectBtn.OnTapped = func() {
		disconnectBtn.Disable()
		statusLabel.SetText("Status: Disconnecting...")
		go func() {
			if err := s.menuDownClick(); err != nil {
				log.Errorf("disconnect failed: %v", err)
				statusLabel.SetText(fmt.Sprintf("Status: Error - %v", err))
			}
			updateUI()
		}()
	}

	content := container.NewVBox(
		layout.NewSpacer(),
		statusLabel,
		layout.NewSpacer(),
		container.NewHBox(
			layout.NewSpacer(),
			connectBtn,
			disconnectBtn,
			layout.NewSpacer(),
		),
		layout.NewSpacer(),
	)

	s.wQuickActions.SetContent(content)
	s.wQuickActions.Resize(fyne.NewSize(300, 150))
	s.wQuickActions.SetFixedSize(true)
	s.wQuickActions.Show()

	updateUI()
}
