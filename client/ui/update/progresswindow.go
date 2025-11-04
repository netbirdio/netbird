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
	resultErrCh     chan error
	resultOkCh      chan struct{}
}

func NewUI() *UI {
	// Create the Fyne application.
	a := app.NewWithID("NetBird-update")

	return &UI{
		app:         a,
		resultErrCh: make(chan error, 1),
		resultOkCh:  make(chan struct{}, 1),
	}
}

func (u *UI) Run() {
	u.app.Run()
}

func (u *UI) ShowUpdateProgress(ctx context.Context, version string) {
	log.Infof("show installer progress window")
	u.wUpdateProgress = u.app.NewWindow("Automatically updating client")

	infoLabel := widget.NewLabel(fmt.Sprintf("Your client version is older than the auto-update version set in Management.\nUpdating client to %s.", version))
	statusLabel := widget.NewLabel("Updating...")
	content := container.NewVBox(infoLabel, statusLabel)
	u.wUpdateProgress.SetContent(content)
	u.wUpdateProgress.CenterOnScreen()
	u.wUpdateProgress.SetFixedSize(true)
	u.wUpdateProgress.SetCloseIntercept(func() {
		// prevent closing this window until a result
	})
	u.wUpdateProgress.RequestFocus()
	u.wUpdateProgress.Show()

	// Initialize dot updater
	updateText := dotUpdater()

	// Update UI with dots and wait for result
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				u.wUpdateProgress.SetCloseIntercept(u.closeApp)
				u.showInstallerResult(statusLabel, ctx.Err())
				return
			case err := <-u.resultErrCh:
				u.wUpdateProgress.SetCloseIntercept(u.closeApp)
				u.showInstallerResult(statusLabel, err)
				return
			case <-u.resultOkCh:
				u.wUpdateProgress.SetCloseIntercept(u.closeApp)
				u.wUpdateProgress.Close()
				return
			case <-ticker.C:
				statusLabel.SetText(updateText())
			}
		}
	}()
}

func (u *UI) UpdateSuccess() {
	select {
	case u.resultOkCh <- struct{}{}:
		log.Infof("update success signal sent")
	default:
		log.Warnf("could not send update success signal - channel full or already processed")
	}
}

func (u *UI) SetError(err error) {
	if err == nil {
		return
	}
	select {
	case u.resultErrCh <- err:
		log.Infof("update error signal sent: %v", err)
	default:
		log.Warnf("could not send update error signal - channel full or already processed")
	}
}

func (u *UI) showInstallerResult(statusLabel *widget.Label, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		log.Warn("update timed out")
		statusLabel.SetText("Update timed out. Please try again.")
	case errors.Is(err, context.Canceled):
		log.Info("update canceled")
		statusLabel.SetText("Update canceled.")
	case err != nil:
		log.Errorf("update failed: %v", err)
		statusLabel.SetText("Update failed: " + err.Error())
	default:
		u.wUpdateProgress.Close()
	}
}

func (u *UI) closeApp() {
	log.Infof("close updater UI app")
	u.app.Quit()
}

// dotUpdater returns a closure that cycles through dots for a loading animation.
func dotUpdater() func() string {
	dotCount := 0
	return func() string {
		dotCount = (dotCount + 1) % 4
		return fmt.Sprintf("%s%s", "Updating", strings.Repeat(".", dotCount))
	}
}
