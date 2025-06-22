//go:build !(linux && 386)

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"fyne.io/fyne/v2"
	"fyne.io/systray"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

type eventHandler struct {
	client *serviceClient
}

func newEventHandler(client *serviceClient) *eventHandler {
	return &eventHandler{
		client: client,
	}
}

func (h *eventHandler) listen(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.client.mUp.ClickedCh:
			h.handleConnectClick()
		case <-h.client.mDown.ClickedCh:
			h.handleDisconnectClick()
		case <-h.client.mAllowSSH.ClickedCh:
			h.handleAllowSSHClick()
		case <-h.client.mAutoConnect.ClickedCh:
			h.handleAutoConnectClick()
		case <-h.client.mEnableRosenpass.ClickedCh:
			h.handleRosenpassClick()
		case <-h.client.mLazyConnEnabled.ClickedCh:
			h.handleLazyConnectionClick()
		case <-h.client.mBlockInbound.ClickedCh:
			h.handleBlockInboundClick()
		case <-h.client.mAdvancedSettings.ClickedCh:
			h.handleAdvancedSettingsClick()
		case <-h.client.mCreateDebugBundle.ClickedCh:
			h.handleCreateDebugBundleClick()
		case <-h.client.mQuit.ClickedCh:
			h.handleQuitClick()
			return
		case <-h.client.mGitHub.ClickedCh:
			h.handleGitHubClick()
		case <-h.client.mUpdate.ClickedCh:
			h.handleUpdateClick()
		case <-h.client.mNetworks.ClickedCh:
			h.handleNetworksClick()
		case <-h.client.mNotifications.ClickedCh:
			h.handleNotificationsClick()
		}
	}
}

func (h *eventHandler) handleConnectClick() {
	h.client.mUp.Disable()
	go func() {
		defer h.client.mUp.Enable()
		if err := h.client.menuUpClick(); err != nil {
			h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to connect to NetBird service"))
		}
	}()
}

func (h *eventHandler) handleDisconnectClick() {
	h.client.mDown.Disable()
	go func() {
		defer h.client.mDown.Enable()
		if err := h.client.menuDownClick(); err != nil {
			h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to connect to NetBird daemon"))
		}
	}()
}

func (h *eventHandler) handleAllowSSHClick() {
	h.toggleCheckbox(h.client.mAllowSSH)
	h.updateConfigWithErr()
}

func (h *eventHandler) handleAutoConnectClick() {
	h.toggleCheckbox(h.client.mAutoConnect)
	h.updateConfigWithErr()
}

func (h *eventHandler) handleRosenpassClick() {
	h.toggleCheckbox(h.client.mEnableRosenpass)
	h.updateConfigWithErr()
}

func (h *eventHandler) handleLazyConnectionClick() {
	h.toggleCheckbox(h.client.mLazyConnEnabled)
	h.updateConfigWithErr()
}

func (h *eventHandler) handleBlockInboundClick() {
	h.toggleCheckbox(h.client.mBlockInbound)
	h.updateConfigWithErr()
}

func (h *eventHandler) handleNotificationsClick() {
	h.toggleCheckbox(h.client.mNotifications)
	if h.client.eventManager != nil {
		h.client.eventManager.SetNotificationsEnabled(h.client.mNotifications.Checked())
	}
	h.updateConfigWithErr()
}

func (h *eventHandler) handleAdvancedSettingsClick() {
	h.client.mAdvancedSettings.Disable()
	go func() {
		defer h.client.mAdvancedSettings.Enable()
		defer h.client.getSrvConfig()
		h.runSelfCommand(h.client.ctx, "settings", "true")
	}()
}

func (h *eventHandler) handleCreateDebugBundleClick() {
	h.client.mCreateDebugBundle.Disable()
	go func() {
		defer h.client.mCreateDebugBundle.Enable()
		h.runSelfCommand(h.client.ctx, "debug", "true")
	}()
}

func (h *eventHandler) handleQuitClick() {
	systray.Quit()
}

func (h *eventHandler) handleGitHubClick() {
	if err := openURL("https://github.com/netbirdio/netbird"); err != nil {
		log.Errorf("failed to open GitHub URL: %v", err)
	}
}

func (h *eventHandler) handleUpdateClick() {
	if err := openURL(version.DownloadUrl()); err != nil {
		log.Errorf("failed to open download URL: %v", err)
	}
}

func (h *eventHandler) handleNetworksClick() {
	h.client.mNetworks.Disable()
	go func() {
		defer h.client.mNetworks.Enable()
		h.runSelfCommand(h.client.ctx, "networks", "true")
	}()
}

func (h *eventHandler) toggleCheckbox(item *systray.MenuItem) {
	if item.Checked() {
		item.Uncheck()
	} else {
		item.Check()
	}
}

func (h *eventHandler) updateConfigWithErr() {
	if err := h.client.updateConfig(); err != nil {
		log.Errorf("failed to update config: %v", err)
	}
}

func (h *eventHandler) runSelfCommand(ctx context.Context, command, arg string) {
	proc, err := os.Executable()
	if err != nil {
		log.Errorf("error getting executable path: %v", err)
		return
	}

	cmd := exec.CommandContext(ctx, proc,
		fmt.Sprintf("--%s=%s", command, arg),
		fmt.Sprintf("--daemon-addr=%s", h.client.addr),
	)

	if out := h.client.attachOutput(cmd); out != nil {
		defer func() {
			if err := out.Close(); err != nil {
				log.Errorf("error closing log file %s: %v", h.client.logFile, err)
			}
		}()
	}

	log.Printf("running command: %s --%s=%s --daemon-addr=%s", proc, command, arg, h.client.addr)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			log.Printf("command '%s %s' failed with exit code %d", command, arg, exitErr.ExitCode())
		}
		return
	}

	log.Printf("command '%s %s' completed successfully", command, arg)
}
