//go:build !(linux && 386)

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

func (s *serviceClient) showUpdateProgress(ctx context.Context, version string) {
	log.Infof("show installer progress window: %s", version)
	s.wUpdateProgress = s.app.NewWindow("Automatically updating client")

	statusLabel := widget.NewLabel("Updating...")
	infoLabel := widget.NewLabel(fmt.Sprintf("Your client version is older than the auto-update version set in Management.\nUpdating client to: %s.", version))
	content := container.NewVBox(infoLabel, statusLabel)
	s.wUpdateProgress.SetContent(content)
	s.wUpdateProgress.CenterOnScreen()
	s.wUpdateProgress.SetFixedSize(true)
	s.wUpdateProgress.SetCloseIntercept(func() {
		// this is empty to lock window until result known
	})
	s.wUpdateProgress.RequestFocus()
	s.wUpdateProgress.Show()

	updateWindowCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)

	// Initialize dot updater
	updateText := dotUpdater()

	// Channel to receive the result from RPC call
	resultErrCh := make(chan error, 1)
	resultOkCh := make(chan struct{}, 1)

	// Start RPC call in background
	go func() {
		conn, err := s.getSrvClient(defaultFailTimeout)
		if err != nil {
			log.Infof("backend not reachable, upgrade in progress: %v", err)
			close(resultOkCh)
			return
		}

		resp, err := conn.GetInstallerResult(updateWindowCtx, &proto.InstallerResultRequest{})
		if err != nil {
			log.Infof("backend stopped responding, upgrade in progress: %v", err)
			close(resultOkCh)
			return
		}

		if !resp.Success {
			resultErrCh <- mapInstallError(resp.ErrorMsg)
			return
		}

		// Success
		close(resultOkCh)
	}()

	// Update UI with dots and wait for result
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer cancel()

		// allow closing update window after 10 sec
		timerResetCloseInterceptor := time.NewTimer(10 * time.Second)
		defer timerResetCloseInterceptor.Stop()

		for {
			select {
			case <-updateWindowCtx.Done():
				s.showInstallerResult(statusLabel, updateWindowCtx.Err())
				return
			case err := <-resultErrCh:
				s.showInstallerResult(statusLabel, err)
				return
			case <-resultOkCh:
				log.Info("backend exited, upgrade in progress, closing all UI")
				killParentUIProcess()
				s.app.Quit()
				return
			case <-ticker.C:
				statusLabel.SetText(updateText())
			case <-timerResetCloseInterceptor.C:
				s.wUpdateProgress.SetCloseIntercept(nil)
			}
		}
	}()
}

func (s *serviceClient) showInstallerResult(statusLabel *widget.Label, err error) {
	s.wUpdateProgress.SetCloseIntercept(nil)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		log.Warn("update watcher timed out")
		statusLabel.SetText("Update timed out. Please try again.")
	case errors.Is(err, context.Canceled):
		log.Info("update watcher canceled")
		statusLabel.SetText("Update canceled.")
	case err != nil:
		log.Errorf("update failed: %v", err)
		statusLabel.SetText("Update failed: " + err.Error())
	default:
		s.wUpdateProgress.Close()
	}
}

// dotUpdater returns a closure that cycles through dots for a loading animation.
func dotUpdater() func() string {
	dotCount := 0
	return func() string {
		dotCount = (dotCount + 1) % 4
		return fmt.Sprintf("%s%s", "Updating", strings.Repeat(".", dotCount))
	}
}

func mapInstallError(msg string) error {
	msg = strings.ToLower(strings.TrimSpace(msg))

	switch {
	case strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "timeout"):
		return context.DeadlineExceeded
	case strings.Contains(msg, "canceled"), strings.Contains(msg, "cancelled"):
		return context.Canceled
	case msg == "":
		return errors.New("unknown update error")
	default:
		return errors.New(msg)
	}
}
