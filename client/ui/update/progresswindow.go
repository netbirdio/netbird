package update

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"
)

type UI struct {
	app             fyne.App
	wUpdateProgress fyne.Window
}

func NewUI() *UI {
	// Create the Fyne application.
	a := app.NewWithID("NetBird-update")

	return &UI{
		app: a,
	}
}

func (u *UI) Run() {
	u.app.Run()
}

func (u *UI) ShowUpdateProgress(ctx context.Context) {
	log.Infof("show installer progress window")
	u.wUpdateProgress = u.app.NewWindow("Automatically updating client")

	statusLabel := widget.NewLabel("Updating...")
	infoLabel := widget.NewLabel("Your client version is older than the auto-update version set in Management.\nUpdating client now.")
	content := container.NewVBox(infoLabel, statusLabel)
	u.wUpdateProgress.SetContent(content)
	u.wUpdateProgress.CenterOnScreen()
	u.wUpdateProgress.SetFixedSize(true)
	u.wUpdateProgress.SetCloseIntercept(func() {}) // lock window until result known
	u.wUpdateProgress.RequestFocus()
	u.wUpdateProgress.Show()

	// Initialize dot updater
	updateText := dotUpdater()

	// Channel to receive the result from RPC call
	resultErrCh := make(chan error, 1)
	resultOkCh := make(chan struct{}, 1)

	// Update UI with dots and wait for result
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				u.showInstallerResult(statusLabel, ctx.Err())
				return
			case err := <-resultErrCh:
				u.showInstallerResult(statusLabel, err)
				return
			case <-resultOkCh:
				u.wUpdateProgress.SetCloseIntercept(nil)
				u.wUpdateProgress.Close()
				return
			case <-ticker.C:
				statusLabel.SetText(updateText())
			}
		}
	}()
}

func (u *UI) showInstallerResult(statusLabel *widget.Label, err error) {
	u.wUpdateProgress.SetCloseIntercept(nil)
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
		u.wUpdateProgress.Close()
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
