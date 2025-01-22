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
	"fyne.io/fyne/v2/dialog"
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
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/client/ui/event"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

const (
	defaultFailTimeout = 3 * time.Second
	failFastTimeout    = time.Second
)

func main() {
	var daemonAddr string

	defaultDaemonAddr := "unix:///var/run/netbird.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}

	flag.StringVar(
		&daemonAddr, "daemon-addr",
		defaultDaemonAddr,
		"Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")

	var showSettings bool
	flag.BoolVar(&showSettings, "settings", false, "run settings windows")
	var showRoutes bool
	flag.BoolVar(&showRoutes, "networks", false, "run networks windows")
	var errorMSG string
	flag.StringVar(&errorMSG, "error-msg", "", "displays a error message window")

	tmpDir := "/tmp"
	if runtime.GOOS == "windows" {
		tmpDir = os.TempDir()
	}

	var saveLogsInFile bool
	flag.BoolVar(&saveLogsInFile, "use-log-file", false, fmt.Sprintf("save logs in a file: %s/netbird-ui-PID.log", tmpDir))

	flag.Parse()

	if saveLogsInFile {
		logFile := path.Join(tmpDir, fmt.Sprintf("netbird-ui-%d.log", os.Getpid()))
		err := util.InitLog("trace", logFile)
		if err != nil {
			log.Errorf("error while initializing log: %v", err)
			return
		}
	}

	a := app.NewWithID("NetBird")
	a.SetIcon(fyne.NewStaticResource("netbird", iconDisconnected))

	if errorMSG != "" {
		showErrorMSG(errorMSG)
		return
	}

	client := newServiceClient(daemonAddr, a, showSettings, showRoutes)
	settingsChangeChan := make(chan fyne.Settings)
	a.Settings().AddChangeListener(settingsChangeChan)
	go func() {
		for range settingsChangeChan {
			client.updateIcon()
		}
	}()

	if showSettings || showRoutes {
		a.Run()
	} else {
		running, err := isAnotherProcessRunning()
		if err != nil {
			log.Errorf("error while checking process: %v", err)
		}
		if running {
			log.Warn("another process is running")
			return
		}
		client.setDefaultFonts()
		systray.Run(client.onTrayReady, client.onTrayExit)
	}
}

//go:embed netbird-systemtray-connected-macos.png
var iconConnectedMacOS []byte

//go:embed netbird-systemtray-disconnected-macos.png
var iconDisconnectedMacOS []byte

//go:embed netbird-systemtray-update-disconnected-macos.png
var iconUpdateDisconnectedMacOS []byte

//go:embed netbird-systemtray-update-connected-macos.png
var iconUpdateConnectedMacOS []byte

//go:embed netbird-systemtray-connecting-macos.png
var iconConnectingMacOS []byte

//go:embed netbird-systemtray-error-macos.png
var iconErrorMacOS []byte

type serviceClient struct {
	ctx  context.Context
	addr string
	conn proto.DaemonServiceClient

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
	mAdminPanel        *systray.MenuItem
	mSettings          *systray.MenuItem
	mAbout             *systray.MenuItem
	mVersionUI         *systray.MenuItem
	mVersionDaemon     *systray.MenuItem
	mUpdate            *systray.MenuItem
	mQuit              *systray.MenuItem
	mNetworks          *systray.MenuItem
	mAllowSSH          *systray.MenuItem
	mAutoConnect       *systray.MenuItem
	mEnableRosenpass   *systray.MenuItem
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

	// observable settings over corresponding iMngURL and iPreSharedKey values.
	managementURL       string
	preSharedKey        string
	adminURL            string
	RosenpassPermissive bool
	interfaceName       string
	interfacePort       int

	connected            bool
	update               *version.Update
	daemonVersion        string
	updateIndicationLock sync.Mutex
	isUpdateIconActive   bool
	showRoutes           bool
	wRoutes              fyne.Window

	eventManager *event.Manager

	exitNodeMu     sync.Mutex
	mExitNodeItems []menuHandler
}

type menuHandler struct {
	*systray.MenuItem
	cancel context.CancelFunc
}

// newServiceClient instance constructor
//
// This constructor also builds the UI elements for the settings window.
func newServiceClient(addr string, a fyne.App, showSettings bool, showRoutes bool) *serviceClient {
	s := &serviceClient{
		ctx:              context.Background(),
		addr:             addr,
		app:              a,
		sendNotification: false,

		showAdvancedSettings: showSettings,
		showRoutes:           showRoutes,
		update:               version.NewUpdate(),
	}

	s.setNewIcons()

	if showSettings {
		s.showSettingsUI()
		return s
	} else if showRoutes {
		s.showNetworksUI()
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

	s.wSettings.SetContent(s.getSettingsForm())
	s.wSettings.Resize(fyne.NewSize(600, 400))
	s.wSettings.SetFixedSize(true)

	s.getSrvConfig()

	s.wSettings.Show()
}

// showErrorMSG opens a fyne app window to display the supplied message
func showErrorMSG(msg string) {
	app := app.New()
	w := app.NewWindow("NetBird Error")
	content := widget.NewLabel(msg)
	content.Wrapping = fyne.TextWrapWord
	w.SetContent(content)
	w.Resize(fyne.NewSize(400, 100))
	w.Show()
	app.Run()
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
		},
		SubmitText: "Save",
		OnSubmit: func() {
			if s.iPreSharedKey.Text != "" && s.iPreSharedKey.Text != "**********" {
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

			// If the management URL, pre-shared key, admin URL, Rosenpass permissive mode,
			// interface name, or interface port have changed, we attempt to re-login with the new settings.
			if s.managementURL != iMngURL || s.preSharedKey != s.iPreSharedKey.Text ||
				s.adminURL != iAdminURL || s.RosenpassPermissive != s.sRosenpassPermissive.Checked ||
				s.interfaceName != s.iInterfaceName.Text || s.interfacePort != int(port) {

				s.managementURL = iMngURL
				s.preSharedKey = s.iPreSharedKey.Text
				s.adminURL = iAdminURL

				loginRequest := proto.LoginRequest{
					ManagementUrl:        iMngURL,
					AdminURL:             iAdminURL,
					IsLinuxDesktopClient: runtime.GOOS == "linux",
					RosenpassPermissive:  &s.sRosenpassPermissive.Checked,
					InterfaceName:        &s.iInterfaceName.Text,
					WireguardPort:        &port,
				}

				if s.iPreSharedKey.Text != "**********" {
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

func (s *serviceClient) login() error {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	loginResp, err := conn.Login(s.ctx, &proto.LoginRequest{
		IsLinuxDesktopClient: runtime.GOOS == "linux",
	})
	if err != nil {
		log.Errorf("login to management URL with: %v", err)
		return err
	}

	if loginResp.NeedsSSOLogin {
		err = open.Run(loginResp.VerificationURIComplete)
		if err != nil {
			log.Errorf("opening the verification uri in the browser failed: %v", err)
			return err
		}

		_, err = conn.WaitSSOLogin(s.ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
		if err != nil {
			log.Errorf("waiting sso login failed with: %v", err)
			return err
		}
	}

	return nil
}

func (s *serviceClient) menuUpClick() error {
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		systray.SetTemplateIcon(iconErrorMacOS, s.icError)
		log.Errorf("get client: %v", err)
		return err
	}

	err = s.login()
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
		return err
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

	if status.Status != string(internal.StatusConnected) {
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
		if status.Status == string(internal.StatusNeedsLogin) {
			s.onSessionExpire()
		}

		var systrayIconState bool
		if status.Status == string(internal.StatusConnected) && !s.mUp.Disabled() {
			s.connected = true
			s.sendNotification = true
			if s.isUpdateIconActive {
				systray.SetTemplateIcon(iconUpdateConnectedMacOS, s.icUpdateConnected)
			} else {
				systray.SetTemplateIcon(iconConnectedMacOS, s.icConnected)
			}
			s.mAbout.SetIcon(s.icConnected)
			systray.SetTooltip("NetBird (Connected)")
			s.mStatus.SetTitle("Connected")
			s.mUp.Disable()
			s.mDown.Enable()
			s.mNetworks.Enable()
			go s.updateExitNodes()
			systrayIconState = true
		} else if status.Status != string(internal.StatusConnected) && s.mUp.Disabled() {
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
	s.mAbout.SetIcon(s.icDisconnected)
	systray.SetTooltip("NetBird (Disconnected)")
	s.mStatus.SetTitle("Disconnected")
	s.mDown.Disable()
	s.mUp.Enable()
	s.mNetworks.Disable()
	go s.updateExitNodes()
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
	s.mAdminPanel = systray.AddMenuItem("Admin Panel", "Netbird Admin Panel")
	systray.AddSeparator()

	s.mSettings = systray.AddMenuItem("Settings", "Settings of the application")
	s.mAllowSSH = s.mSettings.AddSubMenuItemCheckbox("Allow SSH", "Allow SSH connections", false)
	s.mAutoConnect = s.mSettings.AddSubMenuItemCheckbox("Connect on Startup", "Connect automatically when the service starts", false)
	s.mEnableRosenpass = s.mSettings.AddSubMenuItemCheckbox("Enable Quantum-Resistance", "Enable post-quantum security via Rosenpass", false)
	s.mNotifications = s.mSettings.AddSubMenuItemCheckbox("Notifications", "Enable notifications", true)
	s.mAdvancedSettings = s.mSettings.AddSubMenuItem("Advanced Settings", "Advanced settings of the application")
	s.mCreateDebugBundle = s.mSettings.AddSubMenuItem("Create Debug Bundle", "Create and open debug information bundle")
	s.loadSettings()

	s.exitNodeMu.Lock()
	s.mExitNode = systray.AddMenuItem("Exit Node", "Select exit node for routing traffic")
	s.mExitNode.Disable()
	s.exitNodeMu.Unlock()

	s.mNetworks = systray.AddMenuItem("Networks", "Open the networks management window")
	s.mNetworks.Disable()
	systray.AddSeparator()

	s.mAbout = systray.AddMenuItem("About", "About")
	s.mAbout.SetIcon(s.icAbout)
	versionString := normalizedVersion(version.NetbirdVersion())
	s.mVersionUI = s.mAbout.AddSubMenuItem(fmt.Sprintf("GUI: %s", versionString), fmt.Sprintf("GUI Version: %s", versionString))
	s.mVersionUI.Disable()

	s.mVersionDaemon = s.mAbout.AddSubMenuItem("", "")
	s.mVersionDaemon.Disable()
	s.mVersionDaemon.Hide()

	s.mUpdate = s.mAbout.AddSubMenuItem("Download latest version", "Download latest version")
	s.mUpdate.Hide()

	systray.AddSeparator()
	s.mQuit = systray.AddMenuItem("Quit", "Quit the client app")

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

	go func() {
		var err error
		for {
			select {
			case <-s.mAdminPanel.ClickedCh:
				err = open.Run(s.adminURL)
			case <-s.mUp.ClickedCh:
				s.mUp.Disable()
				go func() {
					defer s.mUp.Enable()
					err := s.menuUpClick()
					if err != nil {
						s.app.SendNotification(fyne.NewNotification("Error", "Failed to connect to NetBird service"))
						return
					}
				}()
			case <-s.mDown.ClickedCh:
				s.mDown.Disable()
				go func() {
					defer s.mDown.Enable()
					err := s.menuDownClick()
					if err != nil {
						s.app.SendNotification(fyne.NewNotification("Error", "Failed to connect to NetBird service"))
						return
					}
				}()
			case <-s.mAllowSSH.ClickedCh:
				if s.mAllowSSH.Checked() {
					s.mAllowSSH.Uncheck()
				} else {
					s.mAllowSSH.Check()
				}
				if err := s.updateConfig(); err != nil {
					log.Errorf("failed to update config: %v", err)
				}
			case <-s.mAutoConnect.ClickedCh:
				if s.mAutoConnect.Checked() {
					s.mAutoConnect.Uncheck()
				} else {
					s.mAutoConnect.Check()
				}
				if err := s.updateConfig(); err != nil {
					log.Errorf("failed to update config: %v", err)
				}
			case <-s.mEnableRosenpass.ClickedCh:
				if s.mEnableRosenpass.Checked() {
					s.mEnableRosenpass.Uncheck()
				} else {
					s.mEnableRosenpass.Check()
				}
				if err := s.updateConfig(); err != nil {
					log.Errorf("failed to update config: %v", err)
				}
			case <-s.mNotifications.ClickedCh:
				if s.mNotifications.Checked() {
					s.mNotifications.Uncheck()
				} else {
					s.mNotifications.Check()
				}
				if s.eventManager != nil {
					s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
				}
				if err := s.updateConfig(); err != nil {
					log.Errorf("failed to update config: %v", err)
					return
				}
			case <-s.mAdvancedSettings.ClickedCh:
				s.mAdvancedSettings.Disable()
				go func() {
					defer s.mAdvancedSettings.Enable()
					defer s.getSrvConfig()
					s.runSelfCommand("settings", "true")
				}()
			case <-s.mCreateDebugBundle.ClickedCh:
				go func() {
					if err := s.createAndOpenDebugBundle(); err != nil {
						log.Errorf("Failed to create debug bundle: %v", err)
						s.app.SendNotification(fyne.NewNotification("Error", "Failed to create debug bundle"))
					}
				}()
			case <-s.mQuit.ClickedCh:
				systray.Quit()
				return
			case <-s.mUpdate.ClickedCh:
				err := openURL(version.DownloadUrl())
				if err != nil {
					log.Errorf("%s", err)
				}
			case <-s.mNetworks.ClickedCh:
				s.mNetworks.Disable()
				go func() {
					defer s.mNetworks.Enable()
					s.runSelfCommand("networks", "true")
				}()
			case <-s.mNotifications.ClickedCh:
				if s.mNotifications.Checked() {
					s.mNotifications.Uncheck()
				} else {
					s.mNotifications.Check()
				}
				if s.eventManager != nil {
					s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
				}
				if err := s.updateConfig(); err != nil {
					log.Errorf("failed to update config: %v", err)
				}
			}

			if err != nil {
				log.Errorf("process connection: %v", err)
			}
		}
	}()
}

func (s *serviceClient) runSelfCommand(command, arg string) {
	proc, err := os.Executable()
	if err != nil {
		log.Errorf("show %s failed with error: %v", command, err)
		return
	}

	cmd := exec.Command(proc,
		fmt.Sprintf("--%s=%s", command, arg),
		fmt.Sprintf("--daemon-addr=%s", s.addr),
	)

	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		log.Errorf("start %s UI: %v, %s", command, err, string(out))
		return
	}
	if len(out) != 0 {
		log.Infof("command %s executed: %s", command, string(out))
	}
}

func normalizedVersion(version string) string {
	versionString := version
	if unicode.IsDigit(rune(versionString[0])) {
		versionString = fmt.Sprintf("v%s", versionString)
	}
	return versionString
}

func (s *serviceClient) onTrayExit() {
	for _, item := range s.mExitNodeItems {
		item.cancel()
	}
}

// getSrvClient connection to the service.
func (s *serviceClient) getSrvClient(timeout time.Duration) (proto.DaemonServiceClient, error) {
	if s.conn != nil {
		return s.conn, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		strings.TrimPrefix(s.addr, "tcp://"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithUserAgent(system.GetDesktopUIUserAgent()),
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
	if s.sendNotification {
		title := "Connection session expired"
		if runtime.GOOS == "darwin" {
			title = "NetBird connection session expired"
		}
		s.app.SendNotification(
			fyne.NewNotification(
				title,
				"Please re-authenticate to connect to the network",
			),
		)
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
	notificationsDisabled := !s.mNotifications.Checked()

	loginRequest := proto.LoginRequest{
		IsLinuxDesktopClient: runtime.GOOS == "linux",
		ServerSSHAllowed:     &sshAllowed,
		RosenpassEnabled:     &rosenpassEnabled,
		DisableAutoConnect:   &disableAutoStart,
		DisableNotifications: &notificationsDisabled,
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
