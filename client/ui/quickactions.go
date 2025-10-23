//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

type quickActionsUiState struct {
	connectionStatus string

	statusLabelText           string
	isConnectButtonEnabled    bool
	isDisconnectButtonEnabled bool
}

func newQuickActionsUiState() quickActionsUiState {
	return quickActionsUiState{
		connectionStatus:          "idle",
		statusLabelText:           "",
		isConnectButtonEnabled:    false,
		isDisconnectButtonEnabled: false,
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
					uiState.statusLabelText = fmt.Sprintf("Status: Error - %v", err)
					uiChan <- uiState
				}

				if connectionStatus == "Connected" {
					uiState.isConnectButtonEnabled = false
					uiState.isDisconnectButtonEnabled = true
				} else if connectionStatus == "Idle" {
					uiState.isConnectButtonEnabled = true
					uiState.isDisconnectButtonEnabled = false
				}

				uiState.statusLabelText = fmt.Sprintf("Connection status: %s", connectionStatus)
				uiChan <- uiState
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	return viewModel
}

func (q *quickActionsViewModel) connectClient() {
	uiState := newQuickActionsUiState()
	uiState.statusLabelText = "Connection status: connecting..."

	q.uiChan <- uiState

	q.pauseChan <- struct{}{}
	err := q.connect.execute()

	if err != nil {
		uiState = newQuickActionsUiState()
		uiState.statusLabelText = fmt.Sprintf("Status: Error - %v", err)
		q.uiChan <- uiState
	} else {
		q.resumeChan <- struct{}{}
	}
}

func (q *quickActionsViewModel) disconnectClient() {
	uiState := newQuickActionsUiState()
	uiState.statusLabelText = "Connection status: disconnecting..."

	q.uiChan <- uiState

	q.pauseChan <- struct{}{}
	err := q.disconnect.execute()

	if err != nil {
		uiState = newQuickActionsUiState()
		uiState.statusLabelText = fmt.Sprintf("Status: Error - %v", err)
		q.uiChan <- uiState
	} else {
		q.resumeChan <- struct{}{}
	}
}

// showQuickActionsUI displays a simple window with connect/disconnect controls.
func (s *serviceClient) showQuickActionsUI() {
	s.wQuickActions = s.app.NewWindow("NetBird")
	s.wQuickActions.SetOnClosed(s.cancel)

	statusLabel := widget.NewLabel("Status: Checking...")
	connectBtn := widget.NewButton("Connect", nil)
	disconnectBtn := widget.NewButton("Disconnect", nil)

	client, err := s.getSrvClient(defaultFailTimeout)

	connCmd := connectCommand{
		connectClient: s.menuUpClick,
	}

	disConnCmd := disconnectCommand{
		disconnectClient: s.menuDownClick,
	}

	if err != nil {
		log.Errorf("get service client: %v", err)
		statusLabel.SetText("Status: Error connecting to daemon")
		connectBtn.Disable()
		disconnectBtn.Disable()
		return
	}

	uiChan := make(chan quickActionsUiState, 1)
	viewModel := newQuickActionsViewModel(daemonClientConnectionStatusProvider{client: client}, connCmd, disConnCmd, uiChan)

	// this watches for ui state updates.
	go func() {
		for {
			select {
			case uiState := <-uiChan:
				log.Debugf("uiState.statusLabelText: %v", uiState.statusLabelText)
				statusLabel.SetText(uiState.statusLabelText)
				if uiState.isConnectButtonEnabled {
					connectBtn.Enable()
				} else {
					connectBtn.Disable()
				}

				if uiState.isDisconnectButtonEnabled {
					disconnectBtn.Enable()
				} else {
					disconnectBtn.Disable()
				}
			}
		}
	}()

	connectBtn.OnTapped = func() {
		go func() {
			viewModel.connectClient()
		}()
	}

	disconnectBtn.OnTapped = func() {
		go func() {
			viewModel.disconnectClient()
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
}
