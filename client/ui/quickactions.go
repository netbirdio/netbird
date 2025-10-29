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
	log "github.com/sirupsen/logrus"

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
		connectionStatus:      "Idle",
		isToggleButtonEnabled: false,
		isConnectionChanged:   false,
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
					uiState.toggleAction = func() {
						viewModel.executeCommand(disconnect)
					}
				} else {
					uiState.toggleAction = func() {
						viewModel.executeCommand(connect)
					}
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

func (q *quickActionsViewModel) executeCommand(command clientCommand) {
	uiState := newQuickActionsUiState()
	uiState.connectionStatus = ""

	q.uiChan <- uiState
	q.pauseChan <- struct{}{}

	err := command.execute()

	if err != nil {
		log.Errorf("Status: Error - %v", err)
	} else {
		uiState = newQuickActionsUiState()
		uiState.isConnectionChanged = true
		q.uiChan <- uiState
		//q.resumeChan <- struct{}{}
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

// showQuickActionsUI displays a simple window with the NetBird logo and a connection toggle button.
func (s *serviceClient) showQuickActionsUI() {
	s.wQuickActions = s.app.NewWindow("NetBird")
	s.wQuickActions.SetOnClosed(s.cancel)

	client, err := s.getSrvClient(defaultFailTimeout)

	connCmd := connectCommand{
		connectClient: func() error {
			return s.menuUpClick()
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
	newQuickActionsViewModel(daemonClientConnectionStatusProvider{client: client}, connCmd, disConnCmd, uiChan)

	connectedImage := s.getNetBirdImage("netbird.png", iconAbout)
	disconnectedImage := s.getNetBirdImage("netbird-disconnected.png", iconAboutDisconnected)

	connectedCircle := canvas.NewImageFromResource(resourceConnectedPng)
	disconnectedCircle := canvas.NewImageFromResource(resourceDisconnectedPng)

	connectedLabelText := "Disconnect"
	disconnectedLabelText := "Connect"

	toggleConnectionButton := widget.NewButtonWithIcon(disconnectedLabelText, disconnectedCircle.Resource, func() {
		// This button's tap function will be set when an ui state arrives via the uiChan channel.
	})

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
		var logo *canvas.Image
		var buttonText string
		var buttonIcon fyne.Resource

		for {
			select {
			case uiState := <-uiChan:
				if uiState.isConnectionChanged {
					fyne.DoAndWait(func() {
						s.wQuickActions.Close()
					})

					return
				}

				if uiState.connectionStatus == "Connected" {
					buttonText = connectedLabelText
					buttonIcon = connectedCircle.Resource
					logo = connectedImage
				} else if uiState.connectionStatus == "Idle" {
					buttonText = disconnectedLabelText
					buttonIcon = disconnectedCircle.Resource
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
			}
		}
	}()

	s.wQuickActions.SetContent(content)
	s.wQuickActions.Resize(fyne.NewSize(400, 200))
	s.wQuickActions.SetFixedSize(true)
	s.wQuickActions.Show()
}
