//go:build !(linux && 386)

package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
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

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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
	flags := parseFlags()

	// Initialize file logging if needed.
	var logFile string
	if flags.saveLogsInFile {
		file, err := initLogFile()
		if err != nil {
			log.Errorf("error while initializing log: %v", err)
			return
		}
		logFile = file
	} else {
		_ = util.InitLog("trace", util.LogConsole)
	}

	// Create the Fyne application.
	a := app.NewWithID("NetBird")
	a.SetIcon(fyne.NewStaticResource("netbird", iconDisconnected))

	// Show error message window if needed.
	if flags.errorMsg != "" {
		showErrorMessage(flags.errorMsg)
		return
	}

	// Create the service client (this also builds the settings or networks UI if requested).
	client := newServiceClient(&newServiceClientArgs{
		addr:         flags.daemonAddr,
		logFile:      logFile,
		app:          a,
		showSettings: flags.showSettings,
		showNetworks: flags.showNetworks,
		showLoginURL: flags.showLoginURL,
		showDebug:    flags.showDebug,
		showProfiles: flags.showProfiles,
	})

	// Watch for theme/settings changes to update the icon.
	go watchSettingsChanges(a, client)

	// Run in window mode if any UI flag was set.
	if flags.showSettings || flags.showNetworks || flags.showDebug || flags.showLoginURL || flags.showProfiles {
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

type cliFlags struct {
	daemonAddr     string
	showSettings   bool
	showNetworks   bool
	showProfiles   bool
	showDebug      bool
	showLoginURL   bool
	errorMsg       string
	saveLogsInFile bool
}

// parseFlags reads and returns all needed command-line flags.
func parseFlags() *cliFlags {
	var flags cliFlags

	defaultDaemonAddr := "unix:///var/run/netbird.sock"
	if runtime.GOOS == "windows" {
		defaultDaemonAddr = "tcp://127.0.0.1:41731"
	}
	flag.StringVar(&flags.daemonAddr, "daemon-addr", defaultDaemonAddr, "Daemon service address to serve CLI requests [unix|tcp]://[path|host:port]")
	flag.BoolVar(&flags.showSettings, "settings", false, "run settings window")
	flag.BoolVar(&flags.showNetworks, "networks", false, "run networks window")
	flag.BoolVar(&flags.showProfiles, "profiles", false, "run profiles window")
	flag.BoolVar(&flags.showDebug, "debug", false, "run debug window")
	flag.StringVar(&flags.errorMsg, "error-msg", "", "displays an error message window")
	flag.BoolVar(&flags.saveLogsInFile, "use-log-file", false, fmt.Sprintf("save logs in a file: %s/netbird-ui-PID.log", os.TempDir()))
	flag.BoolVar(&flags.showLoginURL, "login-url", false, "show login URL in a popup window")
	flag.Parse()
	return &flags
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

//go:embed assets/connected.png
var iconConnectedDot []byte

//go:embed assets/disconnected.png
var iconDisconnectedDot []byte

type serviceClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	addr   string
	conn   proto.DaemonServiceClient

	eventHandler *eventHandler

	profileManager *profilemanager.ProfileManager

	icAbout              []byte
	icConnected          []byte
	icConnectedDot       []byte
	icDisconnected       []byte
	icDisconnectedDot    []byte
	icUpdateConnected    []byte
	icUpdateDisconnected []byte
	icConnecting         []byte
	icError              []byte

	// systray menu items
	mStatus            *systray.MenuItem
	mUp                *systray.MenuItem
	mDown              *systray.MenuItem
	mSettings          *systray.MenuItem
	mProfile           *profileMenu
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
	iLogFile       *widget.Entry
	iPreSharedKey  *widget.Entry
	iInterfaceName *widget.Entry
	iInterfacePort *widget.Entry
	iMTU           *widget.Entry

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
	RosenpassPermissive bool
	interfaceName       string
	interfacePort       int
	mtu                 uint16
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
	wProfiles            fyne.Window

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

type newServiceClientArgs struct {
	addr         string
	logFile      string
	app          fyne.App
	showSettings bool
	showNetworks bool
	showDebug    bool
	showLoginURL bool
	showProfiles bool
}

// newServiceClient instance constructor
//
// This constructor also builds the UI elements for the settings window.
func newServiceClient(args *newServiceClientArgs) *serviceClient {
	ctx, cancel := context.WithCancel(context.Background())
	s := &serviceClient{
		ctx:              ctx,
		cancel:           cancel,
		addr:             args.addr,
		app:              args.app,
		logFile:          args.logFile,
		sendNotification: false,

		showAdvancedSettings: args.showSettings,
		showNetworks:         args.showNetworks,
		update:               version.NewUpdate("nb/client-ui"),
	}

	s.eventHandler = newEventHandler(s)
	s.profileManager = profilemanager.NewProfileManager()
	s.setNewIcons()

	switch {
	case args.showSettings:
		s.showSettingsUI()
	case args.showNetworks:
		s.showNetworksUI()
	case args.showLoginURL:
		s.showLoginURL()
	case args.showDebug:
		s.showDebugUI()
	case args.showProfiles:
		s.showProfilesUI()
	}

	return s
}

func (s *serviceClient) setNewIcons() {
	s.icAbout = iconAbout
	s.icConnectedDot = iconConnectedDot
	s.icDisconnectedDot = iconDisconnectedDot
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
	// Check if update settings are disabled by daemon
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		// Continue with default behavior if features can't be retrieved
	} else if features != nil && features.DisableUpdateSettings {
		log.Warn("Update settings are disabled by daemon")
		return
	}

	// add settings window UI elements.
	s.wSettings = s.app.NewWindow("NetBird Settings")
	s.wSettings.SetOnClosed(s.cancel)

	s.iMngURL = widget.NewEntry()

	s.iLogFile = widget.NewEntry()
	s.iLogFile.Disable()
	s.iPreSharedKey = widget.NewPasswordEntry()
	s.iInterfaceName = widget.NewEntry()
	s.iInterfacePort = widget.NewEntry()
	s.iMTU = widget.NewEntry()

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

	var activeProfName string
	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
	} else {
		activeProfName = activeProf.Name
	}
	return &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Profile", Widget: widget.NewLabel(activeProfName)},
			{Text: "Quantum-Resistance", Widget: s.sRosenpassPermissive},
			{Text: "Interface Name", Widget: s.iInterfaceName},
			{Text: "Interface Port", Widget: s.iInterfacePort},
			{Text: "MTU", Widget: s.iMTU},
			{Text: "Management URL", Widget: s.iMngURL},
			{Text: "Pre-shared Key", Widget: s.iPreSharedKey},
			{Text: "Log File", Widget: s.iLogFile},
			{Text: "Network Monitor", Widget: s.sNetworkMonitor},
			{Text: "Disable DNS", Widget: s.sDisableDNS},
			{Text: "Disable Client Routes", Widget: s.sDisableClientRoutes},
			{Text: "Disable Server Routes", Widget: s.sDisableServerRoutes},
			{Text: "Disable LAN Access", Widget: s.sBlockLANAccess},
		},
		SubmitText: "Save",
		OnSubmit: func() {
			// Check if update settings are disabled by daemon
			features, err := s.getFeatures()
			if err != nil {
				log.Errorf("failed to get features from daemon: %v", err)
				// Continue with default behavior if features can't be retrieved
			} else if features != nil && features.DisableUpdateSettings {
				log.Warn("Configuration updates are disabled by daemon")
				dialog.ShowError(fmt.Errorf("Configuration updates are disabled by daemon"), s.wSettings)
				return
			}

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

			var mtu int64
			mtuText := strings.TrimSpace(s.iMTU.Text)
			if mtuText != "" {
				var err error
				mtu, err = strconv.ParseInt(mtuText, 10, 64)
				if err != nil {
					dialog.ShowError(errors.New("Invalid MTU value"), s.wSettings)
					return
				}
				if mtu < iface.MinMTU || mtu > iface.MaxMTU {
					dialog.ShowError(fmt.Errorf("MTU must be between %d and %d bytes", iface.MinMTU, iface.MaxMTU), s.wSettings)
					return
				}
			}

			iMngURL := strings.TrimSpace(s.iMngURL.Text)

			defer s.wSettings.Close()

			// Check if any settings have changed
			if s.managementURL != iMngURL || s.preSharedKey != s.iPreSharedKey.Text ||
				s.RosenpassPermissive != s.sRosenpassPermissive.Checked ||
				s.interfaceName != s.iInterfaceName.Text || s.interfacePort != int(port) ||
				s.mtu != uint16(mtu) ||
				s.networkMonitor != s.sNetworkMonitor.Checked ||
				s.disableDNS != s.sDisableDNS.Checked ||
				s.disableClientRoutes != s.sDisableClientRoutes.Checked ||
				s.disableServerRoutes != s.sDisableServerRoutes.Checked ||
				s.blockLANAccess != s.sBlockLANAccess.Checked {

				s.managementURL = iMngURL
				s.preSharedKey = s.iPreSharedKey.Text
				s.mtu = uint16(mtu)

				currUser, err := user.Current()
				if err != nil {
					log.Errorf("get current user: %v", err)
					return
				}

				var req proto.SetConfigRequest
				req.ProfileName = activeProf.Name
				req.Username = currUser.Username

				if iMngURL != "" {
					req.ManagementUrl = iMngURL
				}

				req.RosenpassPermissive = &s.sRosenpassPermissive.Checked
				req.InterfaceName = &s.iInterfaceName.Text
				req.WireguardPort = &port
				if mtu > 0 {
					req.Mtu = &mtu
				}
				req.NetworkMonitor = &s.sNetworkMonitor.Checked
				req.DisableDns = &s.sDisableDNS.Checked
				req.DisableClientRoutes = &s.sDisableClientRoutes.Checked
				req.DisableServerRoutes = &s.sDisableServerRoutes.Checked
				req.BlockLanAccess = &s.sBlockLANAccess.Checked

				if s.iPreSharedKey.Text != censoredPreSharedKey {
					req.OptionalPreSharedKey = &s.iPreSharedKey.Text
				}

				conn, err := s.getSrvClient(failFastTimeout)
				if err != nil {
					log.Errorf("get client: %v", err)
					dialog.ShowError(fmt.Errorf("Failed to connect to the service: %v", err), s.wSettings)
					return
				}
				_, err = conn.SetConfig(s.ctx, &req)
				if err != nil {
					log.Errorf("set config: %v", err)
					dialog.ShowError(fmt.Errorf("Failed to set configuration: %v", err), s.wSettings)
					return
				}

				go func() {
					status, err := conn.Status(s.ctx, &proto.StatusRequest{})
					if err != nil {
						log.Errorf("get service status: %v", err)
						dialog.ShowError(fmt.Errorf("Failed to get service status: %v", err), s.wSettings)
						return
					}
					if status.Status == string(internal.StatusConnected) {
						// run down & up
						_, err = conn.Down(s.ctx, &proto.DownRequest{})
						if err != nil {
							log.Errorf("down service: %v", err)
						}

						_, err = conn.Up(s.ctx, &proto.UpRequest{})
						if err != nil {
							log.Errorf("up service: %v", err)
							dialog.ShowError(fmt.Errorf("Failed to reconnect: %v", err), s.wSettings)
							return
						}
					}
				}()
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

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
		return nil, err
	}

	currUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}

	loginResp, err := conn.Login(s.ctx, &proto.LoginRequest{
		IsUnixDesktopClient: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
		ProfileName:         &activeProf.Name,
		Username:            &currUser.Username,
	})
	if err != nil {
		log.Errorf("login to management URL with: %v", err)
		return nil, err
	}

	if loginResp.NeedsSSOLogin && openURL {
		err = s.handleSSOLogin(loginResp, conn)
		if err != nil {
			log.Errorf("handle SSO login failed: %v", err)
			return nil, err
		}
	}

	return loginResp, nil
}

func (s *serviceClient) handleSSOLogin(loginResp *proto.LoginResponse, conn proto.DaemonServiceClient) error {
	err := open.Run(loginResp.VerificationURIComplete)
	if err != nil {
		log.Errorf("opening the verification uri in the browser failed: %v", err)
		return err
	}

	resp, err := conn.WaitSSOLogin(s.ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
	if err != nil {
		log.Errorf("waiting sso login failed with: %v", err)
		return err
	}

	if resp.Email != "" {
		err := s.profileManager.SetActiveProfileState(&profilemanager.ProfileState{
			Email: resp.Email,
		})
		if err != nil {
			log.Warnf("failed to set profile state: %v", err)
		} else {
			s.mProfile.refresh()
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
			s.mStatus.SetIcon(s.icConnectedDot)
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
	s.mStatus.SetIcon(s.icDisconnectedDot)
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
	s.mStatus.SetIcon(s.icDisconnectedDot)
	s.mStatus.Disable()

	profileMenuItem := systray.AddMenuItem("", "")
	emailMenuItem := systray.AddMenuItem("", "")

	newProfileMenuArgs := &newProfileMenuArgs{
		ctx:                  s.ctx,
		profileManager:       s.profileManager,
		eventHandler:         s.eventHandler,
		profileMenuItem:      profileMenuItem,
		emailMenuItem:        emailMenuItem,
		downClickCallback:    s.menuDownClick,
		upClickCallback:      s.menuUpClick,
		getSrvClientCallback: s.getSrvClient,
		loadSettingsCallback: s.loadSettings,
		app:                  s.app,
	}

	s.mProfile = newProfileMenu(*newProfileMenuArgs)

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
	s.mSettings.AddSeparator()
	s.mAdvancedSettings = s.mSettings.AddSubMenuItem("Advanced Settings", advancedSettingsMenuDescr)
	s.mCreateDebugBundle = s.mSettings.AddSubMenuItem("Create Debug Bundle", debugBundleMenuDescr)
	s.loadSettings()

	// Disable settings menu if update settings are disabled by daemon
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		// Continue with default behavior if features can't be retrieved
	} else {
		if features != nil && features.DisableUpdateSettings {
			s.setSettingsEnabled(false)
		}
		if features != nil && features.DisableProfiles {
			s.mProfile.setEnabled(false)
		}
	}

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

			// Check features periodically to handle daemon restarts
			s.checkAndUpdateFeatures()

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
		grpc.WithReturnConnectionError(),
		grpc.WithDisableRetry(),
		grpc.FailOnNonTempDialError(true),
		grpc.WithUserAgent(desktop.GetUIUserAgent()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial service: %w", err)
	}

	s.conn = proto.NewDaemonServiceClient(conn)
	return s.conn, nil
}

// setSettingsEnabled enables or disables the settings menu based on the provided state
func (s *serviceClient) setSettingsEnabled(enabled bool) {
	if s.mSettings != nil {
		if enabled {
			s.mSettings.Enable()
			s.mSettings.SetTooltip(settingsMenuDescr)
		} else {
			s.mSettings.Hide()
			s.mSettings.SetTooltip("Settings are disabled by daemon")
		}
	}
}

// checkAndUpdateFeatures checks the current features and updates the UI accordingly
func (s *serviceClient) checkAndUpdateFeatures() {
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		return
	}

	// Update settings menu based on current features
	if features != nil && features.DisableUpdateSettings {
		s.setSettingsEnabled(false)
	} else {
		s.setSettingsEnabled(true)
	}

	// Update profile menu based on current features
	if s.mProfile != nil {
		if features != nil && features.DisableProfiles {
			s.mProfile.setEnabled(false)
		} else {
			s.mProfile.setEnabled(true)
		}
	}
}

// getFeatures from the daemon to determine which features are enabled/disabled.
func (s *serviceClient) getFeatures() (*proto.GetFeaturesResponse, error) {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return nil, fmt.Errorf("get client for features: %w", err)
	}

	features, err := conn.GetFeatures(s.ctx, &proto.GetFeaturesRequest{})
	if err != nil {
		return nil, fmt.Errorf("get features from daemon: %w", err)
	}

	return features, nil
}

// getSrvConfig from the service to show it in the settings window.
func (s *serviceClient) getSrvConfig() {
	s.managementURL = profilemanager.DefaultManagementURL

	_, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
		return
	}

	var cfg *profilemanager.Config

	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	currUser, err := user.Current()
	if err != nil {
		log.Errorf("get current user: %v", err)
		return
	}

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
		return
	}

	srvCfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{
		ProfileName: activeProf.Name,
		Username:    currUser.Username,
	})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return
	}

	cfg = protoConfigToConfig(srvCfg)

	if cfg.ManagementURL.String() != "" {
		s.managementURL = cfg.ManagementURL.String()
	}
	s.preSharedKey = cfg.PreSharedKey
	s.RosenpassPermissive = cfg.RosenpassPermissive
	s.interfaceName = cfg.WgIface
	s.interfacePort = cfg.WgPort
	s.mtu = cfg.MTU

	s.networkMonitor = *cfg.NetworkMonitor
	s.disableDNS = cfg.DisableDNS
	s.disableClientRoutes = cfg.DisableClientRoutes
	s.disableServerRoutes = cfg.DisableServerRoutes
	s.blockLANAccess = cfg.BlockLANAccess

	if s.showAdvancedSettings {
		s.iMngURL.SetText(s.managementURL)
		s.iPreSharedKey.SetText(cfg.PreSharedKey)
		s.iInterfaceName.SetText(cfg.WgIface)
		s.iInterfacePort.SetText(strconv.Itoa(cfg.WgPort))
		if cfg.MTU != 0 {
			s.iMTU.SetText(strconv.Itoa(int(cfg.MTU)))
		} else {
			s.iMTU.SetText("")
			s.iMTU.SetPlaceHolder(strconv.Itoa(int(iface.DefaultMTU)))
		}
		s.sRosenpassPermissive.SetChecked(cfg.RosenpassPermissive)
		if !cfg.RosenpassEnabled {
			s.sRosenpassPermissive.Disable()
		}
		s.sNetworkMonitor.SetChecked(*cfg.NetworkMonitor)
		s.sDisableDNS.SetChecked(cfg.DisableDNS)
		s.sDisableClientRoutes.SetChecked(cfg.DisableClientRoutes)
		s.sDisableServerRoutes.SetChecked(cfg.DisableServerRoutes)
		s.sBlockLANAccess.SetChecked(cfg.BlockLANAccess)
	}

	if s.mNotifications == nil {
		return
	}
	if cfg.DisableNotifications != nil && *cfg.DisableNotifications {
		s.mNotifications.Uncheck()
	} else {
		s.mNotifications.Check()
	}
	if s.eventManager != nil {
		s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
	}
}

func protoConfigToConfig(cfg *proto.GetConfigResponse) *profilemanager.Config {

	var config profilemanager.Config

	if cfg.ManagementUrl != "" {
		parsed, err := url.Parse(cfg.ManagementUrl)
		if err != nil {
			log.Errorf("parse management URL: %v", err)
		} else {
			config.ManagementURL = parsed
		}
	}

	if cfg.PreSharedKey != "" {
		if cfg.PreSharedKey != censoredPreSharedKey {
			config.PreSharedKey = cfg.PreSharedKey
		} else {
			config.PreSharedKey = ""
		}
	}
	if cfg.AdminURL != "" {
		parsed, err := url.Parse(cfg.AdminURL)
		if err != nil {
			log.Errorf("parse admin URL: %v", err)
		} else {
			config.AdminURL = parsed
		}
	}

	config.WgIface = cfg.InterfaceName
	if cfg.WireguardPort != 0 {
		config.WgPort = int(cfg.WireguardPort)
	} else {
		config.WgPort = iface.DefaultWgPort
	}

	if cfg.Mtu != 0 {
		config.MTU = uint16(cfg.Mtu)
	} else {
		config.MTU = iface.DefaultMTU
	}

	config.DisableAutoConnect = cfg.DisableAutoConnect
	config.ServerSSHAllowed = &cfg.ServerSSHAllowed
	config.RosenpassEnabled = cfg.RosenpassEnabled
	config.RosenpassPermissive = cfg.RosenpassPermissive
	config.DisableNotifications = &cfg.DisableNotifications
	config.LazyConnectionEnabled = cfg.LazyConnectionEnabled
	config.BlockInbound = cfg.BlockInbound
	config.NetworkMonitor = &cfg.NetworkMonitor
	config.DisableDNS = cfg.DisableDns
	config.DisableClientRoutes = cfg.DisableClientRoutes
	config.DisableServerRoutes = cfg.DisableServerRoutes
	config.BlockLANAccess = cfg.BlockLanAccess

	return &config
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

	currUser, err := user.Current()
	if err != nil {
		log.Errorf("get current user: %v", err)
		return
	}

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
		return
	}

	cfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{
		ProfileName: activeProf.Name,
		Username:    currUser.Username,
	})
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

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Errorf("get active profile: %v", err)
		return err
	}

	currUser, err := user.Current()
	if err != nil {
		log.Errorf("get current user: %v", err)
		return err
	}

	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return err
	}

	req := proto.SetConfigRequest{
		ProfileName:           activeProf.Name,
		Username:              currUser.Username,
		DisableAutoConnect:    &disableAutoStart,
		ServerSSHAllowed:      &sshAllowed,
		RosenpassEnabled:      &rosenpassEnabled,
		LazyConnectionEnabled: &lazyConnectionEnabled,
		BlockInbound:          &blockInbound,
		DisableNotifications:  &notificationsDisabled,
	}

	if _, err := conn.SetConfig(s.ctx, &req); err != nil {
		log.Errorf("set config settings on server: %v", err)
		return err
	}

	return nil
}

// showLoginURL creates a borderless window styled like a pop-up in the top-right corner using s.wLoginURL.
// It also starts a background goroutine that periodically checks if the client is already connected
// and closes the window if so. The goroutine can be cancelled by the returned CancelFunc, and it is
// also cancelled when the window is closed.
func (s *serviceClient) showLoginURL() context.CancelFunc {

	// create a cancellable context for the background check goroutine
	ctx, cancel := context.WithCancel(s.ctx)

	resIcon := fyne.NewStaticResource("netbird.png", iconAbout)

	if s.wLoginURL == nil {
		s.wLoginURL = s.app.NewWindow("NetBird Session Expired")
		s.wLoginURL.Resize(fyne.NewSize(400, 200))
		s.wLoginURL.SetIcon(resIcon)
	}
	// ensure goroutine is cancelled when the window is closed
	s.wLoginURL.SetOnClosed(func() { cancel() })
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

	// start a goroutine to check connection status and close the window if connected
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		conn, err := s.getSrvClient(failFastTimeout)
		if err != nil {
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status, err := conn.Status(s.ctx, &proto.StatusRequest{})
				if err != nil {
					continue
				}
				if status.Status == string(internal.StatusConnected) {
					if s.wLoginURL != nil {
						s.wLoginURL.Close()
					}
					return
				}
			}
		}
	}()

	s.wLoginURL.Show()

	// return cancel func so callers can stop the background goroutine if desired
	return cancel
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
