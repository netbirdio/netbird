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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
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
		case <-systray.TrayOpenedCh:
			h.client.updateExitNodes()
		}
	}
}

func (h *eventHandler) handleConnectClick() {
	h.client.mUp.Disable()

	if h.client.connectCancel != nil {
		h.client.connectCancel()
	}

	connectCtx, connectCancel := context.WithCancel(h.client.ctx)
	h.client.connectCancel = connectCancel

	go func() {
		defer connectCancel()

		if err := h.client.menuUpClick(connectCtx, true); err != nil {
			st, ok := status.FromError(err)
			if errors.Is(err, context.Canceled) || (ok && st.Code() == codes.Canceled) {
				log.Debugf("connect operation cancelled by user")
			} else {
				h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to connect"))
				log.Errorf("connect failed: %v", err)
			}
		}

		if err := h.client.updateStatus(); err != nil {
			log.Debugf("failed to update status after connect: %v", err)
		}
	}()
}

func (h *eventHandler) handleDisconnectClick() {
	h.client.mDown.Disable()

	h.client.exitNodeStates = []exitNodeState{}

	if h.client.connectCancel != nil {
		log.Debugf("cancelling ongoing connect operation")
		h.client.connectCancel()
		h.client.connectCancel = nil
	}

	go func() {
		if err := h.client.menuDownClick(); err != nil {
			st, ok := status.FromError(err)
			if !errors.Is(err, context.Canceled) && !(ok && st.Code() == codes.Canceled) {
				h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to disconnect"))
				log.Errorf("disconnect failed: %v", err)
			} else {
				log.Debugf("disconnect cancelled or already disconnecting")
			}
		}

		if err := h.client.updateStatus(); err != nil {
			log.Debugf("failed to update status after disconnect: %v", err)
		}
	}()
}

func (h *eventHandler) handleAllowSSHClick() {
	h.toggleCheckbox(h.client.mAllowSSH)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mAllowSSH) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update SSH settings"))
	}

}

func (h *eventHandler) handleAutoConnectClick() {
	h.toggleCheckbox(h.client.mAutoConnect)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mAutoConnect) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update auto-connect settings"))
	}
}

func (h *eventHandler) handleRosenpassClick() {
	h.toggleCheckbox(h.client.mEnableRosenpass)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mEnableRosenpass) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update Rosenpass settings"))
	}
}

func (h *eventHandler) handleLazyConnectionClick() {
	h.toggleCheckbox(h.client.mLazyConnEnabled)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mLazyConnEnabled) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update lazy connection settings"))
	}
}

func (h *eventHandler) handleBlockInboundClick() {
	h.toggleCheckbox(h.client.mBlockInbound)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mBlockInbound) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update block inbound settings"))
	}
}

func (h *eventHandler) handleNotificationsClick() {
	h.toggleCheckbox(h.client.mNotifications)
	if err := h.updateConfigWithErr(); err != nil {
		h.toggleCheckbox(h.client.mNotifications) // revert checkbox state on error
		log.Errorf("failed to update config: %v", err)
		h.client.app.SendNotification(fyne.NewNotification("Error", "Failed to update notifications settings"))
	} else if h.client.eventManager != nil {
		h.client.eventManager.SetNotificationsEnabled(h.client.mNotifications.Checked())
	}

}

func (h *eventHandler) handleAdvancedSettingsClick() {
	h.client.mAdvancedSettings.Disable()
	go func() {
		defer h.client.mAdvancedSettings.Enable()
		defer h.client.getSrvConfig()
		h.runSelfCommand(h.client.ctx, "settings")
	}()
}

func (h *eventHandler) handleCreateDebugBundleClick() {
	h.client.mCreateDebugBundle.Disable()
	go func() {
		defer h.client.mCreateDebugBundle.Enable()
		h.runSelfCommand(h.client.ctx, "debug")
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
		h.runSelfCommand(h.client.ctx, "networks")
	}()
}

func (h *eventHandler) toggleCheckbox(item *systray.MenuItem) {
	if item.Checked() {
		item.Uncheck()
	} else {
		item.Check()
	}
}

func (h *eventHandler) updateConfigWithErr() error {
	if err := h.client.updateConfig(); err != nil {
		return err
	}

	return nil
}

func (h *eventHandler) runSelfCommand(ctx context.Context, command string, args ...string) {
	proc, err := os.Executable()
	if err != nil {
		log.Errorf("error getting executable path: %v", err)
		return
	}

	// Build the full command arguments
	cmdArgs := []string{
		fmt.Sprintf("--%s=true", command),
		fmt.Sprintf("--daemon-addr=%s", h.client.addr),
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.CommandContext(ctx, proc, cmdArgs...)

	if out := h.client.attachOutput(cmd); out != nil {
		defer func() {
			if err := out.Close(); err != nil {
				log.Errorf("error closing log file %s: %v", h.client.logFile, err)
			}
		}()
	}

	log.Printf("running command: %s", cmd.String())

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			log.Printf("command '%s' failed with exit code %d", cmd.String(), exitErr.ExitCode())
		}
		return
	}

	log.Printf("command '%s' completed successfully", cmd.String())
}

func (h *eventHandler) logout(ctx context.Context) error {
	client, err := h.client.getSrvClient(defaultFailTimeout)
	if err != nil {
		return fmt.Errorf("failed to get service client: %w", err)
	}

	_, err = client.Logout(ctx, &proto.LogoutRequest{})
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	h.client.getSrvConfig()

	return nil
}
