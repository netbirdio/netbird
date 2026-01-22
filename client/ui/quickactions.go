//go:build !(linux && 386)

//go:generate fyne bundle -o quickactions_assets.go assets/connected.png
//go:generate fyne bundle -o quickactions_assets.go -append assets/disconnected.png
package main

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

type quickActionsUiState struct {
	connectionStatus      string
	isToggleButtonEnabled bool
	isConnectionChanged   bool
	toggleAction          func()
}

func newQuickActionsUiState() quickActionsUiState {
	return quickActionsUiState{
		connectionStatus:      string(internal.StatusIdle),
		isToggleButtonEnabled: false,
		isConnectionChanged:   false,
	}
}

type clientConnectionStatusProvider interface {
	connectionStatus(ctx context.Context) (string, error)
}

type daemonClientConnectionStatusProvider struct {
	client proto.DaemonServiceClient
}

func (d daemonClientConnectionStatusProvider) connectionStatus(ctx context.Context) (string, error) {
	childCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	status, err := d.client.Status(childCtx, &proto.StatusRequest{})
	if err != nil {
		return "", err
	}

	return status.Status, nil
}

type clientCommand interface {
	execute() error
}

type connectCommand struct {
	connectClient func() error
}

func (c connectCommand) execute() error {
	return c.connectClient()
}

type disconnectCommand struct {
	disconnectClient func() error
}

func (c disconnectCommand) execute() error {
	return c.disconnectClient()
}

type quickActionsViewModel struct {
	provider                   clientConnectionStatusProvider
	connect                    clientCommand
	disconnect                 clientCommand
	uiChan                     chan quickActionsUiState
	isWatchingConnectionStatus atomic.Bool
}

func newQuickActionsViewModel(ctx context.Context, provider clientConnectionStatusProvider, connect, disconnect clientCommand, uiChan chan quickActionsUiState) {
	viewModel := quickActionsViewModel{
		provider:   provider,
		connect:    connect,
		disconnect: disconnect,
		uiChan:     uiChan,
	}

	viewModel.isWatchingConnectionStatus.Store(true)

	// base UI status
	uiChan <- newQuickActionsUiState()

	// this retrieves the current connection status
	// and pushes the UI state that reflects it via uiChan
	go viewModel.watchConnectionStatus(ctx)
}

func (q *quickActionsViewModel) updateUiState(ctx context.Context) {
	uiState := newQuickActionsUiState()
	connectionStatus, err := q.provider.connectionStatus(ctx)

	if err != nil {
		log.Errorf("Status: Error - %v", err)
		q.uiChan <- uiState
		return
	}

	if connectionStatus == string(internal.StatusConnected) {
		uiState.toggleAction = func() {
			q.executeCommand(q.disconnect)
		}
	} else {
		uiState.toggleAction = func() {
			q.executeCommand(q.connect)
		}
	}

	uiState.isToggleButtonEnabled = true
	uiState.connectionStatus = connectionStatus
	q.uiChan <- uiState
}

func (q *quickActionsViewModel) watchConnectionStatus(ctx context.Context) {
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if q.isWatchingConnectionStatus.Load() {
				q.updateUiState(ctx)
			}
		}
	}
}

func (q *quickActionsViewModel) executeCommand(command clientCommand) {
	uiState := newQuickActionsUiState()
	// newQuickActionsUiState starts with Idle connection status,
	// and all that's necessary here is to just disable the toggle button.
	uiState.connectionStatus = ""

	q.uiChan <- uiState

	q.isWatchingConnectionStatus.Store(false)

	err := command.execute()

	if err != nil {
		log.Errorf("Status: Error - %v", err)
		q.isWatchingConnectionStatus.Store(true)
	} else {
		uiState = newQuickActionsUiState()
		uiState.isConnectionChanged = true
		q.uiChan <- uiState
	}
}

func getSystemTrayName() string {
	os := runtime.GOOS
	switch os {
	case "darwin":
		return "menu bar"
	default:
		return "system tray"
	}
}

func (s *serviceClient) getNetBirdImage(name string, content []byte) *canvas.Image {
	imageSize := fyne.NewSize(64, 64)

	resource := fyne.NewStaticResource(name, content)
	image := canvas.NewImageFromResource(resource)
	image.FillMode = canvas.ImageFillContain
	image.SetMinSize(imageSize)
	image.Resize(imageSize)

	return image
}

type quickActionsUiComponents struct {
	content                                   *fyne.Container
	toggleConnectionButton                    *widget.Button
	connectedLabelText, disconnectedLabelText string
	connectedImage, disconnectedImage         *canvas.Image
	connectedCircleRes, disconnectedCircleRes fyne.Resource
}

// applyQuickActionsUiState applies a single UI state to the quick actions window.
// It closes the window and returns true if the connection status has changed,
// in which case the caller should stop processing further states.
func (s *serviceClient) applyQuickActionsUiState(
	uiState quickActionsUiState,
	components quickActionsUiComponents,
) bool {
	if uiState.isConnectionChanged {
		fyne.DoAndWait(func() {
			s.wQuickActions.Close()
		})
		return true
	}

	var logo *canvas.Image
	var buttonText string
	var buttonIcon fyne.Resource

	if uiState.connectionStatus == string(internal.StatusConnected) {
		buttonText = components.connectedLabelText
		buttonIcon = components.connectedCircleRes
		logo = components.connectedImage
	} else if uiState.connectionStatus == string(internal.StatusIdle) {
		buttonText = components.disconnectedLabelText
		buttonIcon = components.disconnectedCircleRes
		logo = components.disconnectedImage
	}

	fyne.DoAndWait(func() {
		if buttonText != "" {
			components.toggleConnectionButton.SetText(buttonText)
		}

		if buttonIcon != nil {
			components.toggleConnectionButton.SetIcon(buttonIcon)
		}

		if uiState.isToggleButtonEnabled {
			components.toggleConnectionButton.Enable()
		} else {
			components.toggleConnectionButton.Disable()
		}

		components.toggleConnectionButton.OnTapped = func() {
			if uiState.toggleAction != nil {
				go uiState.toggleAction()
			}
		}

		components.toggleConnectionButton.Refresh()

		// the second position in the content's object array is the NetBird logo.
		if logo != nil {
			components.content.Objects[1] = logo
			components.content.Refresh()
		}
	})

	return false
}

// showQuickActionsUI displays a simple window with the NetBird logo and a connection toggle button.
func (s *serviceClient) showQuickActionsUI() {
	s.wQuickActions = s.app.NewWindow("NetBird")
	vmCtx, vmCancel := context.WithCancel(s.ctx)
	s.wQuickActions.SetOnClosed(vmCancel)

	client, err := s.getSrvClient(defaultFailTimeout)

	connCmd := connectCommand{
		connectClient: func() error {
			return s.menuUpClick(s.ctx, false)
		},
	}

	disConnCmd := disconnectCommand{
		disconnectClient: func() error {
			return s.menuDownClick()
		},
	}

	if err != nil {
		log.Errorf("get service client: %v", err)
		return
	}

	uiChan := make(chan quickActionsUiState, 1)
	newQuickActionsViewModel(vmCtx, daemonClientConnectionStatusProvider{client: client}, connCmd, disConnCmd, uiChan)

	connectedImage := s.getNetBirdImage("netbird.png", iconAbout)
	disconnectedImage := s.getNetBirdImage("netbird-disconnected.png", iconAboutDisconnected)

	connectedCircle := canvas.NewImageFromResource(resourceConnectedPng)
	disconnectedCircle := canvas.NewImageFromResource(resourceDisconnectedPng)

	connectedLabelText := "Disconnect"
	disconnectedLabelText := "Connect"

	toggleConnectionButton := widget.NewButtonWithIcon(disconnectedLabelText, disconnectedCircle.Resource, func() {
		// This button's tap function will be set when an ui state arrives via the uiChan channel.
	})

	// Button starts disabled until the first ui state arrives.
	toggleConnectionButton.Disable()

	hintLabelText := fmt.Sprintf("You can always access NetBird from your %s.", getSystemTrayName())
	hintLabel := widget.NewLabel(hintLabelText)

	content := container.NewVBox(
		layout.NewSpacer(),
		disconnectedImage,
		layout.NewSpacer(),
		container.NewCenter(toggleConnectionButton),
		layout.NewSpacer(),
		container.NewCenter(hintLabel),
	)

	// this watches for ui state updates.
	go func() {

		for {
			select {
			case <-vmCtx.Done():
				return
			case uiState, ok := <-uiChan:
				if !ok {
					return
				}

				closed := s.applyQuickActionsUiState(
					uiState,
					quickActionsUiComponents{
						content,
						toggleConnectionButton,
						connectedLabelText, disconnectedLabelText,
						connectedImage, disconnectedImage,
						connectedCircle.Resource, disconnectedCircle.Resource,
					},
				)
				if closed {
					return
				}
			}
		}
	}()

	s.wQuickActions.SetContent(content)
	s.wQuickActions.Resize(fyne.NewSize(400, 200))
	s.wQuickActions.SetFixedSize(true)
	s.wQuickActions.Show()
}
