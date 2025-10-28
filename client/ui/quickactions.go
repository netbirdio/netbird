//go:build !(linux && 386)

//go:generate fyne bundle -o quickactions_assets.go assets/connected.png
//go:generate fyne bundle -o quickactions_assets.go -append assets/disconnected.png
package main

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	fynetooltip "github.com/dweymouth/fyne-tooltip"
	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

type quickActionsUiState struct {
	connectionStatus      string
	isToggleButtonEnabled bool
	toggleAction          func()
}

func newQuickActionsUiState() quickActionsUiState {
	return quickActionsUiState{
		connectionStatus:      "Idle",
		isToggleButtonEnabled: false,
		toggleAction:          func() {},
	}
}

type clientConnectionStatusProvider interface {
	connectionStatus() (string, error)
}

type daemonClientConnectionStatusProvider struct {
	client proto.DaemonServiceClient
}

func (d daemonClientConnectionStatusProvider) connectionStatus() (string, error) {
	status, err := d.client.Status(context.Background(), &proto.StatusRequest{})
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
	provider   clientConnectionStatusProvider
	connect    clientCommand
	disconnect clientCommand
	uiChan     chan quickActionsUiState
	pauseChan  chan struct{}
	resumeChan chan struct{}
}

func newQuickActionsViewModel(provider clientConnectionStatusProvider, connect, disconnect clientCommand, uiChan chan quickActionsUiState) quickActionsViewModel {
	viewModel := quickActionsViewModel{
		provider:   provider,
		connect:    connect,
		disconnect: disconnect,
		uiChan:     uiChan,
		pauseChan:  make(chan struct{}),
		resumeChan: make(chan struct{}),
	}

	// base UI status
	uiChan <- newQuickActionsUiState()

	// this retrieves the current connection status
	go func() {
		getConnectionStatus := true

		for {
			select {
			case <-viewModel.pauseChan:
				// pause until resumed.
				getConnectionStatus = false
				log.Debug("uiChan paused.")
			case <-viewModel.resumeChan:
				getConnectionStatus = true
				log.Debug("uiChan resumed.")
			default:
				if !getConnectionStatus {
					continue
				}

				uiState := newQuickActionsUiState()
				connectionStatus, err := provider.connectionStatus()

				if err != nil {
					log.Errorf("Status: Error - %v", err)
					uiChan <- uiState
				}

				if connectionStatus == "Connected" {
					uiState.toggleAction = viewModel.disconnectClient
				} else {
					uiState.toggleAction = viewModel.connectClient
				}

				uiState.isToggleButtonEnabled = true
				uiState.connectionStatus = connectionStatus
				//uiState.statusLabelText = fmt.Sprintf("Connection status: %s", connectionStatus)
				uiChan <- uiState
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	return viewModel
}

func (q *quickActionsViewModel) connectClient() {
	uiState := newQuickActionsUiState()
	uiState.connectionStatus = ""

	q.uiChan <- uiState
	q.pauseChan <- struct{}{}

	err := q.connect.execute()

	if err != nil {
		log.Errorf("Status: Error - %v", err)
	} else {
		q.resumeChan <- struct{}{}
	}
}

func (q *quickActionsViewModel) disconnectClient() {
	uiState := newQuickActionsUiState()
	uiState.connectionStatus = ""

	q.uiChan <- uiState
	q.pauseChan <- struct{}{}

	err := q.disconnect.execute()

	if err != nil {
		log.Errorf("Status: Error - %v", err)
	} else {
		q.resumeChan <- struct{}{}
	}
}

func (s *serviceClient) getSystemTrayName() string {
	os := runtime.GOOS
	switch os {
	case "darwin":
		return "menu bar"
	default:
		return "system tray"
	}
}

// showQuickActionsUI displays a simple window with the NetBird logo and a connection toggle button.
func (s *serviceClient) showQuickActionsUI() {
	s.wQuickActions = s.app.NewWindow("NetBird")
	s.wQuickActions.SetOnClosed(s.cancel)

	client, err := s.getSrvClient(defaultFailTimeout)

	connCmd := connectCommand{
		connectClient: s.menuUpClick,
	}

	disConnCmd := disconnectCommand{
		disconnectClient: s.menuDownClick,
	}

	if err != nil {
		log.Errorf("get service client: %v", err)
		return
	}

	uiChan := make(chan quickActionsUiState, 1)
	newQuickActionsViewModel(daemonClientConnectionStatusProvider{client: client}, connCmd, disConnCmd, uiChan)

	imageSize := fyne.NewSize(64, 64)

	connectedIcon := fyne.NewStaticResource("netbird.png", iconAbout)
	connectedImage := canvas.NewImageFromResource(connectedIcon)
	connectedImage.FillMode = canvas.ImageFillContain
	connectedImage.SetMinSize(imageSize)
	connectedImage.Resize(imageSize)

	disconnectedIcon := fyne.NewStaticResource("netbird-disconnected.png", iconAboutDisconnected)
	disconnectedImage := canvas.NewImageFromResource(disconnectedIcon)
	disconnectedImage.FillMode = canvas.ImageFillContain
	disconnectedImage.SetMinSize(imageSize)
	disconnectedImage.Resize(imageSize)

	connectedCircle := canvas.NewImageFromResource(resourceConnectedPng)
	disconnectedCircle := canvas.NewImageFromResource(resourceDisconnectedPng)

	connectedLabelText := "Disconnect"
	disconnectedLabelText := "Connect"

	toggleConnectionButton := widget.NewButtonWithIcon(disconnectedLabelText, disconnectedCircle.Resource, func() {})

	hintLabelText := fmt.Sprintf("You can always access NetBird from your %s.", s.getSystemTrayName())
	hintLabel := ttwidget.NewLabel(hintLabelText)
	hintLabel.SetToolTip("Test")

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
		var logo *canvas.Image
		var buttonText string
		var buttonIcon fyne.Resource

		for {
			select {
			case uiState := <-uiChan:
				if uiState.connectionStatus == "Connected" {
					buttonText = connectedLabelText
					buttonIcon = connectedCircle.Resource
					//toggleConnectionButton.SetText(connectedLabelText)
					//toggleConnectionButton.SetIcon(connectedCircle.Resource)
					logo = connectedImage
				} else if uiState.connectionStatus == "Idle" {
					buttonText = disconnectedLabelText
					buttonIcon = disconnectedCircle.Resource
					//toggleConnectionButton.SetText(disconnectedLabelText)
					//toggleConnectionButton.SetIcon(disconnectedCircle.Resource)
					logo = disconnectedImage
				}

				fyne.DoAndWait(func() {
					toggleConnectionButton.SetText(buttonText)
					toggleConnectionButton.SetIcon(buttonIcon)
					if uiState.isToggleButtonEnabled {
						toggleConnectionButton.Enable()
					} else {
						toggleConnectionButton.Disable()
					}

					toggleConnectionButton.Refresh()

					// second position in the content's objects array is the NetBird logo.
					content.Objects[1] = logo
					content.Refresh()
				})

				toggleConnectionButton.OnTapped = func() {
					go func() {
						uiState.toggleAction()
					}()
				}
			default:
			}
		}
	}()

	s.wQuickActions.SetContent(fynetooltip.AddWindowToolTipLayer(content, s.wQuickActions.Canvas()))
	s.wQuickActions.Resize(fyne.NewSize(400, 200))
	s.wQuickActions.SetFixedSize(true)
	s.wQuickActions.Show()
}
