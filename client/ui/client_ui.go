//go:build !(linux && 386)

package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"fyne.io/systray"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/desktop"
	"github.com/netbirdio/netbird/client/ui/event"
	"github.com/netbirdio/netbird/client/ui/process"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/version"
)

const (
	defaultFailTimeout = 3 * time.Second
	failFastTimeout    = time.Second
)

const (
	censoredPreSharedKey = "**********"
)

func main() {
	daemonAddr, showSettings, showNetworks, showLoginURL, showDebug, errorMsg, saveLogsInFile := parseFlags()

	// Initialize file logging if needed.
	var logFile string
	if saveLogsInFile {
		file, err := initLogFile()
		if err != nil {
			log.Errorf("error while initializing log: %v", err)
			return
		}
		logFile = file
	} else {
		_ = util.InitLog("trace", "console")
	}

	// Create the Fyne application.
	a := app.NewWithID("NetBird")
	a.SetIcon(fyne.NewStaticResource("netbird", iconDisconnected))

	// Show error message window if needed.
	if errorMsg != "" {
		showErrorMessage(errorMsg)
		return
	}

	// Create the service client (this also builds the settings or networks UI if requested).
	client := newServiceClient(daemonAddr, logFile, a, showSettings, showNetworks, showLoginURL, showDebug)

	// Watch for theme/settings changes to update the icon.
	go watchSettingsChanges(a, client)

	// Run in window mode if any UI flag was set.
	if showSettings || showNetworks || showDebug || showLoginURL {
		a.Run()
		return
	}

	// Check for another running process.
	pid, running, err := process.IsAnotherProcessRunning()
	if err != nil {
		log.Errorf("error while checking process: %v", err)
		return
	}
	if running {
		log.Warnf("another process is running with pid %d, exiting", pid)
		return
	}

	client.setDefaultFonts()
	systray.Run(client.onTrayReady, client.onTrayExit)
}

// parseFlags reads and returns all needed command-line flags.
func parseFlags() (daemonAddr string, showSettings, showNetworks, showLoginURL, showDebug bool, errorMsg string, saveLogsInFile bool) {
	defaultDaemonAddr := "unix:///var/run/netbird.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}
	flag.StringVar(&daemonAddr, "daemon-addr", defaultDaemonAddr, "Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")
	flag.BoolVar(&showSettings, "settings", false, "run settings window")
	flag.BoolVar(&showNetworks, "networks", false, "run networks window")
	flag.BoolVar(&showLoginURL, "login-url", false, "show login URL in a popup window")
	flag.BoolVar(&showDebug, "debug", false, "run debug window")
	flag.StringVar(&errorMsg, "error-msg", "", "displays an error message window")
	flag.BoolVar(&saveLogsInFile, "use-log-file", false, fmt.Sprintf("save logs in a file: %s/netbird-ui-PID.log", os.TempDir()))
	flag.Parse()
	return
}

// initLogFile initializes logging into a file.
func initLogFile() (string, error) {
	logFile := path.Join(os.TempDir(), fmt.Sprintf("netbird-ui-%d.log", os.Getpid()))
	return logFile, util.InitLog("trace", logFile)
}

// watchSettingsChanges listens for Fyne theme/settings changes and updates the client icon.
func watchSettingsChanges(a fyne.App, client *serviceClient) {
	settingsChangeChan := make(chan fyne.Settings)
	a.Settings().AddChangeListener(settingsChangeChan)
	for range settingsChangeChan {
		client.updateIcon()
	}
}

// showErrorMessage displays an error message in a simple window.
func showErrorMessage(msg string) {
	a := app.New()
	w := a.NewWindow("NetBird Error")
	label := widget.NewLabel(msg)
	label.Wrapping = fyne.TextWrapWord
	w.SetContent(label)
	w.Resize(fyne.NewSize(400, 100))
	w.Show()
	a.Run()
}

//go:embed assets/netbird-systemtray-connected-macos.png
var iconConnectedMacOS []byte

//go:embed assets/netbird-systemtray-disconnected-macos.png
var iconDisconnectedMacOS []byte

//go:embed assets/netbird-systemtray-update-disconnected-macos.png
var iconUpdateDisconnectedMacOS []byte

//go:embed assets/netbird-systemtray-update-connected-macos.png
var iconUpdateConnectedMacOS []byte

//go:embed assets/netbird-systemtray-connecting-macos.png
var iconConnectingMacOS []byte

//go:embed assets/netbird-systemtray-error-macos.png
var iconErrorMacOS []byte

type serviceClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	addr   string
	conn   proto.DaemonServiceClient

	eventHandler *eventHandler

	icAbout              []byte
	icConnected          []byte
	icDisconnected       []byte
	icUpdateConnected    []byte
	icUpdateDisconnected []byte
	icConnecting         []byte
	icError              []byte

	// systray menu items
	mStatus            *systray.MenuItem
	mUp                *systray.MenuItem
	mDown              *systray.MenuItem
	mSettings          *systray.MenuItem
	mAbout             *systray.MenuItem
	mGitHub            *systray.MenuItem
	mVersionUI         *systray.MenuItem
	mVersionDaemon     *systray.MenuItem
	mUpdate            *systray.MenuItem
	mQuit              *systray.MenuItem
	mNetworks          *systray.MenuItem
	mAllowSSH          *systray.MenuItem
	mAutoConnect       *systray.MenuItem
	mEnableRosenpass   *systray.MenuItem
	mLazyConnEnabled   *systray.MenuItem
	mBlockInbound      *systray.MenuItem
	mNotifications     *systray.MenuItem
	mAdvancedSettings  *systray.MenuItem
	mCreateDebugBundle *systray.MenuItem
	mExitNode          *systray.MenuItem

	// application with main windows.
	app                  fyne.App
	wSettings            fyne.Window
	showAdvancedSettings bool
	sendNotification     bool

	// input elements for settings form
	iMngURL        *widget.Entry
	iAdminURL      *widget.Entry
	iConfigFile    *widget.Entry
	iLogFile       *widget.Entry
	iPreSharedKey  *widget.Entry
	iInterfaceName *widget.Entry
	iInterfacePort *widget.Entry

	// switch elements for settings form
	sRosenpassPermissive *widget.Check
	sNetworkMonitor      *widget.Check
	sDisableDNS          *widget.Check
	sDisableClientRoutes *widget.Check
	sDisableServerRoutes *widget.Check
	sBlockLANAccess      *widget.Check

	// observable settings over corresponding iMngURL and iPreSharedKey values.
	managementURL       string
	preSharedKey        string
	adminURL            string
	RosenpassPermissive bool
	interfaceName       string
	interfacePort       int
	networkMonitor      bool
	disableDNS          bool
	disableClientRoutes bool
	disableServerRoutes bool
	blockLANAccess      bool

	connected            bool
	update               *version.Update
	daemonVersion        string
	updateIndicationLock sync.Mutex
	isUpdateIconActive   bool
	showNetworks         bool
	wNetworks            fyne.Window

	eventManager *event.Manager

	exitNodeMu           sync.Mutex
	mExitNodeItems       []menuHandler
	exitNodeStates       []exitNodeState
	mExitNodeDeselectAll *systray.MenuItem
	logFile              string
	wLoginURL            fyne.Window
}

type menuHandler struct {
	*systray.MenuItem
	cancel context.CancelFunc
}

// newServiceClient instance constructor
//
// This constructor also builds the UI elements for the settings window.
func newServiceClient(addr string, logFile string, a fyne.App, showSettings bool, showNetworks bool, showLoginURL bool, showDebug bool) *serviceClient {
	ctx, cancel := context.WithCancel(context.Background())
	s := &serviceClient{
		ctx:              ctx,
		cancel:           cancel,
		addr:             addr,
		app:              a,
		logFile:          logFile,
		sendNotification: false,

		showAdvancedSettings: showSettings,
		showNetworks:         showNetworks,
		update:               version.NewUpdate("nb/client-ui"),
	}

	s.eventHandler = newEventHandler(s)
	s.setNewIcons()

	switch {
	case showSettings:
		s.showSettingsUI()
	case showNetworks:
		s.showNetworksUI()
	case showLoginURL:
		s.showLoginURL()
	case showDebug:
		s.showDebugUI()
	}

	return s
}

func (s *serviceClient) setNewIcons() {
	s.icAbout = iconAbout
	if s.app.Settings().ThemeVariant() == theme.VariantDark {
		s.icConnected = iconConnectedDark
		s.icDisconnected = iconDisconnected
		s.icUpdateConnected = iconUpdateConnectedDark
		s.icUpdateDisconnected = iconUpdateDisconnectedDark
		s.icConnecting = iconConnectingDark
		s.icError = iconErrorDark
	} else {
		s.icConnected = iconConnected
		s.icDisconnected = iconDisconnected
		s.icUpdateConnected = iconUpdateConnected
		s.icUpdateDisconnected = iconUpdateDisconnected
		s.icConnecting = iconConnecting
		s.icError = iconError
	}
}

func (s *serviceClient) updateIcon() {
	s.setNewIcons()
	s.updateIndicationLock.Lock()
	if s.connected {
		if s.isUpdateIconActive {
			systray.SetTemplateIcon(iconUpdateConnectedMacOS, s.icUpdateConnected)
		} else {
			systray.SetTemplateIcon(iconConnectedMacOS, s.icConnected)
		}
	} else {
		if s.isUpdateIconActive {
			systray.SetTemplateIcon(iconUpdateDisconnectedMacOS, s.icUpdateDisconnected)
		} else {
			systray.SetTemplateIcon(iconDisconnectedMacOS, s.icDisconnected)
		}
	}
	s.updateIndicationLock.Unlock()
}

func (s *serviceClient) showSettingsUI() {
	// add settings window UI elements.
	s.wSettings = s.app.NewWindow("NetBird Settings")
	s.wSettings.SetOnClosed(s.cancel)

	s.iMngURL = widget.NewEntry()
	s.iAdminURL = widget.NewEntry()
	s.iConfigFile = widget.NewEntry()
	s.iConfigFile.Disable()
	s.iLogFile = widget.NewEntry()
	s.iLogFile.Disable()
	s.iPreSharedKey = widget.NewPasswordEntry()
	s.iInterfaceName = widget.NewEntry()
	s.iInterfacePort = widget.NewEntry()

	s.sRosenpassPermissive = widget.NewCheck("Enable Rosenpass permissive mode", nil)

	s.sNetworkMonitor = widget.NewCheck("Restarts NetBird when the network changes", nil)
	s.sDisableDNS = widget.NewCheck("Keeps system DNS settings unchanged", nil)
	s.sDisableClientRoutes = widget.NewCheck("This peer won't route traffic to other peers", nil)
	s.sDisableServerRoutes = widget.NewCheck("This peer won't act as router for others", nil)
	s.sBlockLANAccess = widget.NewCheck("Blocks local network access when used as exit node", nil)

	s.wSettings.SetContent(s.getSettingsForm())
	s.wSettings.Resize(fyne.NewSize(600, 500))
	s.wSettings.SetFixedSize(true)

	s.getSrvConfig()
	s.wSettings.Show()
}

// getSettingsForm to embed it into settings window.
func (s *serviceClient) getSettingsForm() *widget.Form {
	return &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Quantum-Resistance", Widget: s.sRosenpassPermissive},
			{Text: "Interface Name", Widget: s.iInterfaceName},
			{Text: "Interface Port", Widget: s.iInterfacePort},
			{Text: "Management URL", Widget: s.iMngURL},
			{Text: "Admin URL", Widget: s.iAdminURL},
			{Text: "Pre-shared Key", Widget: s.iPreSharedKey},
			{Text: "Config File", Widget: s.iConfigFile},
			{Text: "Log File", Widget: s.iLogFile},
			{Text: "Network Monitor", Widget: s.sNetworkMonitor},
			{Text: "Disable DNS", Widget: s.sDisableDNS},
			{Text: "Disable Client Routes", Widget: s.sDisableClientRoutes},
			{Text: "Disable Server Routes", Widget: s.sDisableServerRoutes},
			{Text: "Disable LAN Access", Widget: s.sBlockLANAccess},
		},
		SubmitText: "Save",
		OnSubmit: func() {
			if s.iPreSharedKey.Text != "" && s.iPreSharedKey.Text != censoredPreSharedKey {
				// validate preSharedKey if it added
				if _, err := wgtypes.ParseKey(s.iPreSharedKey.Text); err != nil {
					dialog.ShowError(fmt.Errorf("Invalid Pre-shared Key Value"), s.wSettings)
					return
				}
			}

			port, err := strconv.ParseInt(s.iInterfacePort.Text, 10, 64)
			if err != nil {
				dialog.ShowError(errors.New("Invalid interface port"), s.wSettings)
				return
			}

			iAdminURL := strings.TrimSpace(s.iAdminURL.Text)
			iMngURL := strings.TrimSpace(s.iMngURL.Text)

			defer s.wSettings.Close()

			// Check if any settings have changed
			if s.managementURL != iMngURL || s.preSharedKey != s.iPreSharedKey.Text ||
				s.adminURL != iAdminURL || s.RosenpassPermissive != s.sRosenpassPermissive.Checked ||
				s.interfaceName != s.iInterfaceName.Text || s.interfacePort != int(port) ||
				s.networkMonitor != s.sNetworkMonitor.Checked ||
				s.disableDNS != s.sDisableDNS.Checked ||
				s.disableClientRoutes != s.sDisableClientRoutes.Checked ||
				s.disableServerRoutes != s.sDisableServerRoutes.Checked ||
				s.blockLANAccess != s.sBlockLANAccess.Checked {

				s.managementURL = iMngURL
				s.preSharedKey = s.iPreSharedKey.Text
				s.adminURL = iAdminURL

				loginRequest := proto.LoginRequest{
					ManagementUrl:       iMngURL,
					AdminURL:            iAdminURL,
					IsUnixDesktopClient: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
					RosenpassPermissive: &s.sRosenpassPermissive.Checked,
					InterfaceName:       &s.iInterfaceName.Text,
					WireguardPort:       &port,
					NetworkMonitor:      &s.sNetworkMonitor.Checked,
					DisableDns:          &s.sDisableDNS.Checked,
					DisableClientRoutes: &s.sDisableClientRoutes.Checked,
					DisableServerRoutes: &s.sDisableServerRoutes.Checked,
					BlockLanAccess:      &s.sBlockLANAccess.Checked,
				}

				if s.iPreSharedKey.Text != censoredPreSharedKey {
					loginRequest.OptionalPreSharedKey = &s.iPreSharedKey.Text
				}

				if err := s.restartClient(&loginRequest); err != nil {
					log.Errorf("restarting client connection: %v", err)
					return
				}
			}
		},
		OnCancel: func() {
			s.wSettings.Close()
		},
	}
}

func (s *serviceClient) login(openURL bool) (*proto.LoginResponse, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return nil, err
	}

	loginResp, err := conn.Login(s.ctx, &proto.LoginRequest{
		IsUnixDesktopClient: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
	})
	if err != nil {
		log.Errorf("login to management URL with: %v", err)
		return nil, err
	}

	if loginResp.NeedsSSOLogin && openURL {
		err = open.Run(loginResp.VerificationURIComplete)
		if err != nil {
			log.Errorf("opening the verification uri in the browser failed: %v", err)
			return nil, err
		}

		_, err = conn.WaitSSOLogin(s.ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
		if err != nil {
			log.Errorf("waiting sso login failed with: %v", err)
			return nil, err
		}
	}

	return loginResp, nil
}

func (s *serviceClient) menuUpClick() error {
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		systray.SetTemplateIcon(iconErrorMacOS, s.icError)
		log.Errorf("get client: %v", err)
		return err
	}

	_, err = s.login(true)
	if err != nil {
		log.Errorf("login failed with: %v", err)
		return err
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get service status: %v", err)
		return err
	}

	if status.Status == string(internal.StatusConnected) {
		log.Warnf("already connected")
		return nil
	}

	if _, err := s.conn.Up(s.ctx, &proto.UpRequest{}); err != nil {
		log.Errorf("up service: %v", err)
		return err
	}

	return nil
}

func (s *serviceClient) menuDownClick() error {
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		log.Errorf("get service status: %v", err)
		return err
	}

	if status.Status != string(internal.StatusConnected) && status.Status != string(internal.StatusConnecting) {
		log.Warnf("already down")
		return nil
	}

	if _, err := s.conn.Down(s.ctx, &proto.DownRequest{}); err != nil {
		log.Errorf("down service: %v", err)
		return err
	}

	return nil
}

func (s *serviceClient) updateStatus() error {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return err
	}
	err = backoff.Retry(func() error {
		status, err := conn.Status(s.ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("get service status: %v", err)
			if s.connected {
				s.app.SendNotification(fyne.NewNotification("Error", "Connection to service lost"))
			}
			s.setDisconnectedStatus()
			return err
		}

		s.updateIndicationLock.Lock()
		defer s.updateIndicationLock.Unlock()

		// notify the user when the session has expired
		if status.Status == string(internal.StatusSessionExpired) {
			s.onSessionExpire()
		}

		var systrayIconState bool

		switch {
		case status.Status == string(internal.StatusConnected):
			s.connected = true
			s.sendNotification = true
			if s.isUpdateIconActive {
				systray.SetTemplateIcon(iconUpdateConnectedMacOS, s.icUpdateConnected)
			} else {
				systray.SetTemplateIcon(iconConnectedMacOS, s.icConnected)
			}
			systray.SetTooltip("NetBird (Connected)")
			s.mStatus.SetTitle("Connected")
			s.mUp.Disable()
			s.mDown.Enable()
			s.mNetworks.Enable()
			go s.updateExitNodes()
			systrayIconState = true
		case status.Status == string(internal.StatusConnecting):
			s.setConnectingStatus()
		case status.Status != string(internal.StatusConnected) && s.mUp.Disabled():
			s.setDisconnectedStatus()
			systrayIconState = false
		}

		// the updater struct notify by the upgrades available only, but if meanwhile the daemon has successfully
		// updated must reset the mUpdate visibility state
		if s.daemonVersion != status.DaemonVersion {
			s.mUpdate.Hide()
			s.daemonVersion = status.DaemonVersion

			s.isUpdateIconActive = s.update.SetDaemonVersion(status.DaemonVersion)
			if !s.isUpdateIconActive {
				if systrayIconState {
					systray.SetTemplateIcon(iconConnectedMacOS, s.icConnected)
				} else {
					systray.SetTemplateIcon(iconDisconnectedMacOS, s.icDisconnected)
				}
			}

			daemonVersionTitle := normalizedVersion(s.daemonVersion)
			s.mVersionDaemon.SetTitle(fmt.Sprintf("Daemon: %s", daemonVersionTitle))
			s.mVersionDaemon.SetTooltip(fmt.Sprintf("Daemon version: %s", daemonVersionTitle))
			s.mVersionDaemon.Show()
		}

		return nil
	}, &backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         300 * time.Millisecond,
		MaxElapsedTime:      2 * time.Second,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *serviceClient) setDisconnectedStatus() {
	s.connected = false
	if s.isUpdateIconActive {
		systray.SetTemplateIcon(iconUpdateDisconnectedMacOS, s.icUpdateDisconnected)
	} else {
		systray.SetTemplateIcon(iconDisconnectedMacOS, s.icDisconnected)
	}
	systray.SetTooltip("NetBird (Disconnected)")
	s.mStatus.SetTitle("Disconnected")
	s.mDown.Disable()
	s.mUp.Enable()
	s.mNetworks.Disable()
	s.mExitNode.Disable()
	go s.updateExitNodes()
}

func (s *serviceClient) setConnectingStatus() {
	s.connected = false
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	systray.SetTooltip("NetBird (Connecting)")
	s.mStatus.SetTitle("Connecting")
	s.mUp.Disable()
	s.mDown.Enable()
	s.mNetworks.Disable()
	s.mExitNode.Disable()
}

func (s *serviceClient) onTrayReady() {
	systray.SetTemplateIcon(iconDisconnectedMacOS, s.icDisconnected)
	systray.SetTooltip("NetBird")

	// setup systray menu items
	s.mStatus = systray.AddMenuItem("Disconnected", "Disconnected")
	s.mStatus.Disable()
	systray.AddSeparator()
	s.mUp = systray.AddMenuItem("Connect", "Connect")
	s.mDown = systray.AddMenuItem("Disconnect", "Disconnect")
	s.mDown.Disable()
	systray.AddSeparator()

	s.mSettings = systray.AddMenuItem("Settings", settingsMenuDescr)
	s.mAllowSSH = s.mSettings.AddSubMenuItemCheckbox("Allow SSH", allowSSHMenuDescr, false)
	s.mAutoConnect = s.mSettings.AddSubMenuItemCheckbox("Connect on Startup", autoConnectMenuDescr, false)
	s.mEnableRosenpass = s.mSettings.AddSubMenuItemCheckbox("Enable Quantum-Resistance", quantumResistanceMenuDescr, false)
	s.mLazyConnEnabled = s.mSettings.AddSubMenuItemCheckbox("Enable Lazy Connections", lazyConnMenuDescr, false)
	s.mBlockInbound = s.mSettings.AddSubMenuItemCheckbox("Block Inbound Connections", blockInboundMenuDescr, false)
	s.mNotifications = s.mSettings.AddSubMenuItemCheckbox("Notifications", notificationsMenuDescr, false)
	s.mAdvancedSettings = s.mSettings.AddSubMenuItem("Advanced Settings", advancedSettingsMenuDescr)
	s.mCreateDebugBundle = s.mSettings.AddSubMenuItem("Create Debug Bundle", debugBundleMenuDescr)
	s.loadSettings()

	s.exitNodeMu.Lock()
	s.mExitNode = systray.AddMenuItem("Exit Node", exitNodeMenuDescr)
	s.mExitNode.Disable()
	s.exitNodeMu.Unlock()

	s.mNetworks = systray.AddMenuItem("Networks", networksMenuDescr)
	s.mNetworks.Disable()
	systray.AddSeparator()

	s.mAbout = systray.AddMenuItem("About", "About")
	s.mAbout.SetIcon(s.icAbout)

	s.mGitHub = s.mAbout.AddSubMenuItem("GitHub", "GitHub")

	versionString := normalizedVersion(version.NetbirdVersion())
	s.mVersionUI = s.mAbout.AddSubMenuItem(fmt.Sprintf("GUI: %s", versionString), fmt.Sprintf("GUI Version: %s", versionString))
	s.mVersionUI.Disable()

	s.mVersionDaemon = s.mAbout.AddSubMenuItem("", "")
	s.mVersionDaemon.Disable()
	s.mVersionDaemon.Hide()

	s.mUpdate = s.mAbout.AddSubMenuItem("Download latest version", latestVersionMenuDescr)
	s.mUpdate.Hide()

	systray.AddSeparator()
	s.mQuit = systray.AddMenuItem("Quit", quitMenuDescr)

	// update exit node menu in case service is already connected
	go s.updateExitNodes()

	s.update.SetOnUpdateListener(s.onUpdateAvailable)
	go func() {
		s.getSrvConfig()
		time.Sleep(100 * time.Millisecond) // To prevent race condition caused by systray not being fully initialized and ignoring setIcon
		for {
			err := s.updateStatus()
			if err != nil {
				log.Errorf("error while updating status: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	s.eventManager = event.NewManager(s.app, s.addr)
	s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
	s.eventManager.AddHandler(func(event *proto.SystemEvent) {
		if event.Category == proto.SystemEvent_SYSTEM {
			s.updateExitNodes()
		}
	})

	go s.eventManager.Start(s.ctx)
	go s.eventHandler.listen(s.ctx)
}

func (s *serviceClient) attachOutput(cmd *exec.Cmd) *os.File {
	if s.logFile == "" {
		// attach child's streams to parent's streams
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		return nil
	}

	out, err := os.OpenFile(s.logFile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Errorf("Failed to open log file %s: %v", s.logFile, err)
		return nil
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return out
}

func normalizedVersion(version string) string {
	versionString := version
	if unicode.IsDigit(rune(versionString[0])) {
		versionString = fmt.Sprintf("v%s", versionString)
	}
	return versionString
}

// onTrayExit is called when the tray icon is closed.
func (s *serviceClient) onTrayExit() {
	s.cancel()
}

// getSrvClient connection to the service.
func (s *serviceClient) getSrvClient(timeout time.Duration) (proto.DaemonServiceClient, error) {
	if s.conn != nil {
		return s.conn, nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		strings.TrimPrefix(s.addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithUserAgent(desktop.GetUIUserAgent()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial service: %w", err)
	}

	s.conn = proto.NewDaemonServiceClient(conn)
	return s.conn, nil
}

// getSrvConfig from the service to show it in the settings window.
func (s *serviceClient) getSrvConfig() {
	s.managementURL = internal.DefaultManagementURL
	s.adminURL = internal.DefaultAdminURL

	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	cfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return
	}

	if cfg.ManagementUrl != "" {
		s.managementURL = cfg.ManagementUrl
	}
	if cfg.AdminURL != "" {
		s.adminURL = cfg.AdminURL
	}
	s.preSharedKey = cfg.PreSharedKey
	s.RosenpassPermissive = cfg.RosenpassPermissive
	s.interfaceName = cfg.InterfaceName
	s.interfacePort = int(cfg.WireguardPort)

	s.networkMonitor = cfg.NetworkMonitor
	s.disableDNS = cfg.DisableDns
	s.disableClientRoutes = cfg.DisableClientRoutes
	s.disableServerRoutes = cfg.DisableServerRoutes
	s.blockLANAccess = cfg.BlockLanAccess

	if s.showAdvancedSettings {
		s.iMngURL.SetText(s.managementURL)
		s.iAdminURL.SetText(s.adminURL)
		s.iConfigFile.SetText(cfg.ConfigFile)
		s.iLogFile.SetText(cfg.LogFile)
		s.iPreSharedKey.SetText(cfg.PreSharedKey)
		s.iInterfaceName.SetText(cfg.InterfaceName)
		s.iInterfacePort.SetText(strconv.Itoa(int(cfg.WireguardPort)))
		s.sRosenpassPermissive.SetChecked(cfg.RosenpassPermissive)
		if !cfg.RosenpassEnabled {
			s.sRosenpassPermissive.Disable()
		}
		s.sNetworkMonitor.SetChecked(cfg.NetworkMonitor)
		s.sDisableDNS.SetChecked(cfg.DisableDns)
		s.sDisableClientRoutes.SetChecked(cfg.DisableClientRoutes)
		s.sDisableServerRoutes.SetChecked(cfg.DisableServerRoutes)
		s.sBlockLANAccess.SetChecked(cfg.BlockLanAccess)
	}

	if s.mNotifications == nil {
		return
	}
	if cfg.DisableNotifications {
		s.mNotifications.Uncheck()
	} else {
		s.mNotifications.Check()
	}
	if s.eventManager != nil {
		s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
	}
}

func (s *serviceClient) onUpdateAvailable() {
	s.updateIndicationLock.Lock()
	defer s.updateIndicationLock.Unlock()

	s.mUpdate.Show()
	s.isUpdateIconActive = true

	if s.connected {
		systray.SetTemplateIcon(iconUpdateConnectedMacOS, s.icUpdateConnected)
	} else {
		systray.SetTemplateIcon(iconUpdateDisconnectedMacOS, s.icUpdateDisconnected)
	}
}

// onSessionExpire sends a notification to the user when the session expires.
func (s *serviceClient) onSessionExpire() {
	s.sendNotification = true
	if s.sendNotification {
		go s.eventHandler.runSelfCommand(s.ctx, "login-url", "true")
		s.sendNotification = false
	}
}

// loadSettings loads the settings from the config file and updates the UI elements accordingly.
func (s *serviceClient) loadSettings() {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	cfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return
	}

	if cfg.ServerSSHAllowed {
		s.mAllowSSH.Check()
	} else {
		s.mAllowSSH.Uncheck()
	}

	if cfg.DisableAutoConnect {
		s.mAutoConnect.Uncheck()
	} else {
		s.mAutoConnect.Check()
	}

	if cfg.RosenpassEnabled {
		s.mEnableRosenpass.Check()
	} else {
		s.mEnableRosenpass.Uncheck()
	}

	if cfg.LazyConnectionEnabled {
		s.mLazyConnEnabled.Check()
	} else {
		s.mLazyConnEnabled.Uncheck()
	}

	if cfg.BlockInbound {
		s.mBlockInbound.Check()
	} else {
		s.mBlockInbound.Uncheck()
	}

	if cfg.DisableNotifications {
		s.mNotifications.Uncheck()
	} else {
		s.mNotifications.Check()
	}
	if s.eventManager != nil {
		s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
	}
}

// updateConfig updates the configuration parameters
// based on the values selected in the settings window.
func (s *serviceClient) updateConfig() error {
	disableAutoStart := !s.mAutoConnect.Checked()
	sshAllowed := s.mAllowSSH.Checked()
	rosenpassEnabled := s.mEnableRosenpass.Checked()
	lazyConnectionEnabled := s.mLazyConnEnabled.Checked()
	blockInbound := s.mBlockInbound.Checked()
	notificationsDisabled := !s.mNotifications.Checked()

	loginRequest := proto.LoginRequest{
		IsUnixDesktopClient:   runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
		ServerSSHAllowed:      &sshAllowed,
		RosenpassEnabled:      &rosenpassEnabled,
		DisableAutoConnect:    &disableAutoStart,
		DisableNotifications:  &notificationsDisabled,
		LazyConnectionEnabled: &lazyConnectionEnabled,
		BlockInbound:          &blockInbound,
	}

	if err := s.restartClient(&loginRequest); err != nil {
		log.Errorf("restarting client connection: %v", err)
		return err
	}

	return nil
}

// restartClient restarts the client connection.
func (s *serviceClient) restartClient(loginRequest *proto.LoginRequest) error {
	ctx, cancel := context.WithTimeout(s.ctx, defaultFailTimeout)
	defer cancel()

	client, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return err
	}

	_, err = client.Login(ctx, loginRequest)
	if err != nil {
		return err
	}

	_, err = client.Up(ctx, &proto.UpRequest{})
	if err != nil {
		return err
	}

	return nil
}

// showLoginURL creates a borderless window styled like a pop-up in the top-right corner using s.wLoginURL.
func (s *serviceClient) showLoginURL() {

	resIcon := fyne.NewStaticResource("netbird.png", iconAbout)

	if s.wLoginURL == nil {
		s.wLoginURL = s.app.NewWindow("NetBird Session Expired")
		s.wLoginURL.Resize(fyne.NewSize(400, 200))
		s.wLoginURL.SetIcon(resIcon)
	}
	// add a description label
	label := widget.NewLabel("Your NetBird session has expired.\nPlease re-authenticate to continue using NetBird.")

	btn := widget.NewButtonWithIcon("Re-authenticate", theme.ViewRefreshIcon(), func() {

		conn, err := s.getSrvClient(defaultFailTimeout)
		if err != nil {
			log.Errorf("get client: %v", err)
			return
		}

		resp, err := s.login(false)
		if err != nil {
			log.Errorf("failed to fetch login URL: %v", err)
			return
		}
		verificationURL := resp.VerificationURIComplete
		if verificationURL == "" {
			verificationURL = resp.VerificationURI
		}

		if verificationURL == "" {
			log.Error("no verification URL provided in the login response")
			return
		}

		if err := openURL(verificationURL); err != nil {
			log.Errorf("failed to open login URL: %v", err)
			return
		}

		_, err = conn.WaitSSOLogin(s.ctx, &proto.WaitSSOLoginRequest{UserCode: resp.UserCode})
		if err != nil {
			log.Errorf("Waiting sso login failed with: %v", err)
			label.SetText("Waiting login failed, please create \na debug bundle in the settings and contact support.")
			return
		}

		label.SetText("Re-authentication successful.\nReconnecting")
		status, err := conn.Status(s.ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("get service status: %v", err)
			return
		}

		if status.Status == string(internal.StatusConnected) {
			label.SetText("Already connected.\nClosing this window.")
			time.Sleep(2 * time.Second)
			s.wLoginURL.Close()
			return
		}

		_, err = conn.Up(s.ctx, &proto.UpRequest{})
		if err != nil {
			label.SetText("Reconnecting failed, please create \na debug bundle in the settings and contact support.")
			log.Errorf("Reconnecting failed with: %v", err)
			return
		}

		label.SetText("Connection successful.\nClosing this window.")
		time.Sleep(time.Second)

		s.wLoginURL.Close()
	})

	img := canvas.NewImageFromResource(resIcon)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(64, 64))
	img.Resize(fyne.NewSize(64, 64))

	// center the content vertically
	content := container.NewVBox(
		layout.NewSpacer(),
		img,
		label,
		btn,
		layout.NewSpacer(),
	)
	s.wLoginURL.SetContent(container.NewCenter(content))

	s.wLoginURL.Show()
}

func openURL(url string) error {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux", "freebsd":
		err = exec.Command("xdg-open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}
