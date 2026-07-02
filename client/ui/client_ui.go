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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
	daddr "github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/ui/desktop"
	"github.com/netbirdio/netbird/client/ui/event"
	"github.com/netbirdio/netbird/client/ui/notifier"
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
	maxSSHJWTCacheTTL    = 86_400 // 24 hours in seconds
	// mdmFieldSuffix is appended to plain-text Entry widgets in the
	// advanced Settings window when the underlying field is enforced
	// by MDM, so the user sees the lock indicator inline next to the
	// value. Stripped before any read site that feeds the value back
	// into a SetConfig request (saveSettings / parseNumericSettings).
	mdmFieldSuffix = " (MDM)"
)

// main is the entry point for the UI tray/client binary. Parses CLI
// flags, initialises logging, builds the Fyne application and tray
// icons, and constructs the service client (which may open a
// requested UI window). When a window-mode flag is set the Fyne event
// loop runs and main returns; otherwise main enforces single-instance
// behaviour (signalling an existing instance to show its window when
// present), sets up signal handling + default fonts, and runs the
// system tray loop.
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
		addr:              flags.daemonAddr,
		logFile:           logFile,
		app:               a,
		showSettings:      flags.showSettings,
		showNetworks:      flags.showNetworks,
		showLoginURL:      flags.showLoginURL,
		showDebug:         flags.showDebug,
		showProfiles:      flags.showProfiles,
		showQuickActions:  flags.showQuickActions,
		showUpdate:        flags.showUpdate,
		showUpdateVersion: flags.showUpdateVersion,
	})

	// Watch for theme/settings changes to update the icon.
	go watchSettingsChanges(a, client)

	// Run in window mode if any UI flag was set.
	if flags.showSettings || flags.showNetworks || flags.showDebug || flags.showLoginURL || flags.showProfiles || flags.showQuickActions || flags.showUpdate {
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
		log.Infof("another process is running with pid %d, sending signal to show window", pid)
		if err := sendShowWindowSignal(pid); err != nil {
			log.Errorf("send signal to running instance: %v", err)
		}
		return
	}

	client.setupSignalHandler(client.ctx)

	client.setDefaultFonts()
	systray.Run(client.onTrayReady, client.onTrayExit)
}

type cliFlags struct {
	daemonAddr        string
	showSettings      bool
	showNetworks      bool
	showProfiles      bool
	showDebug         bool
	showLoginURL      bool
	showQuickActions  bool
	errorMsg          string
	saveLogsInFile    bool
	showUpdate        bool
	showUpdateVersion string
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
	flag.BoolVar(&flags.showQuickActions, "quick-actions", false, "run quick actions window")
	flag.StringVar(&flags.errorMsg, "error-msg", "", "displays an error message window")
	flag.BoolVar(&flags.saveLogsInFile, "use-log-file", false, fmt.Sprintf("save logs in a file: %s/netbird-ui-PID.log", os.TempDir()))
	flag.BoolVar(&flags.showLoginURL, "login-url", false, "show login URL in a popup window")
	flag.BoolVar(&flags.showUpdate, "update", false, "show update progress window")
	flag.StringVar(&flags.showUpdateVersion, "update-version", "", "version to update to")
	flag.Parse()


	flags.daemonAddr = daddr.ResolveUnixDaemonAddr(flags.daemonAddr)
	return &flags
}

// initLogFile initializes logging into a file.
func initLogFile() (string, error) {
	logFile := path.Join(os.TempDir(), fmt.Sprintf("netbird-ui-%d.log", os.Getpid()))
	return logFile, util.InitLog("trace", logFile)
}

// watchSettingsChanges listens for Fyne theme/settings changes and updates the client icon.
func watchSettingsChanges(a fyne.App, client *serviceClient) {
	a.Settings().AddListener(func(settings fyne.Settings) {
		client.updateIcon()
	})
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
	ctx      context.Context
	cancel   context.CancelFunc
	addr     string
	conn     proto.DaemonServiceClient
	connLock sync.Mutex

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
	notifier             notifier.Notifier
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
	sRosenpassPermissive        *widget.Check
	sNetworkMonitor             *widget.Check
	sDisableDNS                 *widget.Check
	sDisableClientRoutes        *widget.Check
	sDisableServerRoutes        *widget.Check
	sDisableIPv6                *widget.Check
	sBlockLANAccess             *widget.Check
	sEnableSSHRoot              *widget.Check
	sEnableSSHSFTP              *widget.Check
	sEnableSSHLocalPortForward  *widget.Check
	sEnableSSHRemotePortForward *widget.Check
	sDisableSSHAuth             *widget.Check
	iSSHJWTCacheTTL             *widget.Entry

	// observable settings over corresponding iMngURL and iPreSharedKey values.
	managementURL string
	preSharedKey  string

	RosenpassPermissive        bool
	interfaceName              string
	interfacePort              int
	mtu                        uint16
	networkMonitor             bool
	disableDNS                 bool
	disableClientRoutes        bool
	disableServerRoutes        bool
	disableIPv6                bool
	blockLANAccess             bool
	enableSSHRoot              bool
	enableSSHSFTP              bool
	enableSSHLocalPortForward  bool
	enableSSHRemotePortForward bool
	disableSSHAuth             bool
	sshJWTCacheTTL             int

	connected            bool
	daemonVersion        string
	updateIndicationLock sync.Mutex
	isUpdateIconActive   bool
	isEnforcedUpdate     bool
	lastNotifiedVersion  string
	profilesEnabled      bool
	networksEnabled      bool
	// networksMenuEnabled caches the last applied enabled-state of the
	// mNetworks + mExitNode submenu items. Combines features.DisableNetworks
	// AND s.connected — both must be true for the menus to be active.
	// Zero value (false) matches the Disable() call at AddMenuItem time.
	networksMenuEnabled  bool
	showNetworks         bool
	wNetworks            fyne.Window
	wProfiles            fyne.Window
	wQuickActions        fyne.Window

	eventManager *event.Manager

	exitNodeMu           sync.Mutex
	mExitNodeItems       []menuHandler
	exitNodeRetryCancel  context.CancelFunc
	mExitNodeSeparator   *systray.MenuItem
	mExitNodeDeselectAll *systray.MenuItem
	logFile              string
	wLoginURL            fyne.Window
	wUpdateProgress      fyne.Window
	updateContextCancel  context.CancelFunc

	connectCancel context.CancelFunc

	// mdmManagedFields caches the names of MDM-enforced policy keys
	// surfaced by the daemon in GetConfigResponse. Each refresh of
	// daemon config (loadSettings, getSrvConfig, config_changed event)
	// updates this set and re-applies the lock/badge to the affected
	// menu items and settings-form widgets.
	mdmManagedFields map[string]bool
}

type menuHandler struct {
	*systray.MenuItem
	cancel context.CancelFunc
}

type newServiceClientArgs struct {
	addr              string
	logFile           string
	app               fyne.App
	showSettings      bool
	showNetworks      bool
	showDebug         bool
	showLoginURL      bool
	showProfiles      bool
	showQuickActions  bool
	showUpdate        bool
	showUpdateVersion string
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
		notifier:         notifier.New(args.app),
		logFile:          args.logFile,
		sendNotification: false,

		showAdvancedSettings: args.showSettings,
		showNetworks:         args.showNetworks,
		networksEnabled:      true,
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
	case args.showQuickActions:
		// Suppress the on-boot Quick Actions popup when the daemon
		// reports DisableAutoConnect=true — that flag carries both the
		// user's "Connect on Startup = off" preference AND any MDM-
		// enforced override (applyMDMPolicy writes the policy value
		// into the same Config field). See netbirdio/netbird#5744.
		if !s.disableAutoConnectFromDaemon() {
			s.showQuickActionsUI()
		}
	case args.showUpdate:
		s.showUpdateProgress(ctx, args.showUpdateVersion)
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
	// DisableUpdateSettings no longer gates the window from opening:
	// the daemon blocks every actual mutation at SetConfig / Login,
	// so the window is safe to show as a read-only view. The previous
	// early-return also blocked Advanced Settings whenever update
	// editing was off, which conflated two distinct kill switches
	// (see comment in checkAndUpdateFeatures).

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
	s.sDisableIPv6 = widget.NewCheck("Disable IPv6 overlay addressing", nil)
	s.sBlockLANAccess = widget.NewCheck("Blocks local network access when used as exit node", nil)
	s.sEnableSSHRoot = widget.NewCheck("Enable SSH Root Login", nil)
	s.sEnableSSHSFTP = widget.NewCheck("Enable SSH SFTP", nil)
	s.sEnableSSHLocalPortForward = widget.NewCheck("Enable SSH Local Port Forwarding", nil)
	s.sEnableSSHRemotePortForward = widget.NewCheck("Enable SSH Remote Port Forwarding", nil)
	s.sDisableSSHAuth = widget.NewCheck("Disable SSH Authentication", nil)
	s.iSSHJWTCacheTTL = widget.NewEntry()

	s.wSettings.SetContent(s.getSettingsForm())
	s.wSettings.Resize(fyne.NewSize(600, 400))
	s.wSettings.SetFixedSize(true)

	s.getSrvConfig()
	s.wSettings.Show()
}

func (s *serviceClient) getConnectionForm() *widget.Form {
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
			{Text: "Management URL", Widget: s.iMngURL},
			{Text: "Pre-shared Key", Widget: s.iPreSharedKey},
			{Text: "Quantum-Resistance", Widget: s.sRosenpassPermissive},
			{Text: "Interface Name", Widget: s.iInterfaceName},
			{Text: "Interface Port", Widget: s.iInterfacePort, HintText: "If set to 0, a random free port will be used"},
			{Text: "MTU", Widget: s.iMTU},
			{Text: "Log File", Widget: s.iLogFile},
		},
	}
}

func (s *serviceClient) saveSettings() {
	// Check if update settings are disabled by daemon
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		// Continue with default behavior if features can't be retrieved
	} else if features != nil && features.DisableUpdateSettings {
		log.Warn("Configuration updates are disabled by daemon")
		dialog.ShowError(fmt.Errorf("configuration updates are disabled by daemon"), s.wSettings)
		return
	}

	if err := s.validateSettings(); err != nil {
		dialog.ShowError(err, s.wSettings)
		return
	}

	port, mtu, err := s.parseNumericSettings()
	if err != nil {
		dialog.ShowError(err, s.wSettings)
		return
	}

	iMngURL := strings.TrimSpace(strings.TrimSuffix(s.iMngURL.Text, mdmFieldSuffix))

	if s.hasSettingsChanged(iMngURL, port, mtu) {
		if err := s.applySettingsChanges(iMngURL, port, mtu); err != nil {
			dialog.ShowError(err, s.wSettings)
			return
		}
	}

	s.wSettings.Close()
}

func (s *serviceClient) validateSettings() error {
	if s.iPreSharedKey.Text != "" && s.iPreSharedKey.Text != censoredPreSharedKey {
		if _, err := wgtypes.ParseKey(s.iPreSharedKey.Text); err != nil {
			return fmt.Errorf("invalid pre-shared key value")
		}
	}
	return nil
}

func (s *serviceClient) parseNumericSettings() (int64, int64, error) {
	port, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(s.iInterfacePort.Text, mdmFieldSuffix)), 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid interface port")
	}
	if port < 0 || port > 65535 {
		return 0, 0, errors.New("invalid interface port: out of range 0-65535")
	}

	var mtu int64
	mtuText := strings.TrimSpace(s.iMTU.Text)
	if mtuText != "" {
		mtu, err = strconv.ParseInt(mtuText, 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid MTU value")
		}
		if mtu < iface.MinMTU || mtu > iface.MaxMTU {
			return 0, 0, fmt.Errorf("MTU must be between %d and %d bytes", iface.MinMTU, iface.MaxMTU)
		}
	}

	return port, mtu, nil
}

func (s *serviceClient) hasSettingsChanged(iMngURL string, port, mtu int64) bool {
	return s.managementURL != iMngURL ||
		s.preSharedKey != s.iPreSharedKey.Text ||
		s.RosenpassPermissive != s.sRosenpassPermissive.Checked ||
		s.interfaceName != s.iInterfaceName.Text ||
		s.interfacePort != int(port) ||
		s.mtu != uint16(mtu) ||
		s.networkMonitor != s.sNetworkMonitor.Checked ||
		s.disableDNS != s.sDisableDNS.Checked ||
		s.disableClientRoutes != s.sDisableClientRoutes.Checked ||
		s.disableServerRoutes != s.sDisableServerRoutes.Checked ||
		s.disableIPv6 != s.sDisableIPv6.Checked ||
		s.blockLANAccess != s.sBlockLANAccess.Checked ||
		s.hasSSHChanges()
}

func (s *serviceClient) applySettingsChanges(iMngURL string, port, mtu int64) error {
	s.managementURL = iMngURL
	s.preSharedKey = s.iPreSharedKey.Text
	s.mtu = uint16(mtu)

	req, err := s.buildSetConfigRequest(iMngURL, port, mtu)
	if err != nil {
		return fmt.Errorf("build config request: %w", err)
	}

	if err := s.sendConfigUpdate(req); err != nil {
		return fmt.Errorf("set configuration: %w", err)
	}

	return nil
}

func (s *serviceClient) buildSetConfigRequest(iMngURL string, port, mtu int64) (*proto.SetConfigRequest, error) {
	currUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	req := &proto.SetConfigRequest{
		ProfileName: activeProf.ID.String(),
		Username:    currUser.Username,
	}

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
	req.DisableIpv6 = &s.sDisableIPv6.Checked
	req.BlockLanAccess = &s.sBlockLANAccess.Checked

	req.EnableSSHRoot = &s.sEnableSSHRoot.Checked
	req.EnableSSHSFTP = &s.sEnableSSHSFTP.Checked
	req.EnableSSHLocalPortForwarding = &s.sEnableSSHLocalPortForward.Checked
	req.EnableSSHRemotePortForwarding = &s.sEnableSSHRemotePortForward.Checked
	req.DisableSSHAuth = &s.sDisableSSHAuth.Checked

	sshJWTCacheTTLText := strings.TrimSpace(s.iSSHJWTCacheTTL.Text)
	if sshJWTCacheTTLText != "" {
		sshJWTCacheTTL, err := strconv.ParseInt(sshJWTCacheTTLText, 10, 32)
		if err != nil {
			return nil, errors.New("invalid SSH JWT Cache TTL value")
		}
		if sshJWTCacheTTL < 0 || sshJWTCacheTTL > maxSSHJWTCacheTTL {
			return nil, fmt.Errorf("SSH JWT Cache TTL must be between 0 and %d seconds", maxSSHJWTCacheTTL)
		}
		sshJWTCacheTTL32 := int32(sshJWTCacheTTL)
		req.SshJWTCacheTTL = &sshJWTCacheTTL32
	}

	// Only attach the PSK when the user actually typed something:
	// - "" means the field was left untouched (we deliberately render
	//   an empty Text + placeholder hint to avoid leaking the daemon's
	//   "**********" redaction through the password reveal toggle);
	//   sending an empty pointer would tell the daemon to clear / overwrite
	//   the on-disk or MDM-enforced PSK, which then trips the MDM
	//   conflict gate when PSK is policy-managed.
	// - "**********" is the redacted echo (legacy non-MDM path); also a no-op.
	if s.iPreSharedKey.Text != "" && s.iPreSharedKey.Text != censoredPreSharedKey {
		req.OptionalPreSharedKey = &s.iPreSharedKey.Text
	}

	return req, nil
}

func (s *serviceClient) sendConfigUpdate(req *proto.SetConfigRequest) error {
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	_, err = conn.SetConfig(s.ctx, req)
	if err != nil {
		return fmt.Errorf("set config: %w", err)
	}

	// Reconnect if connected to apply the new settings.
	// Use a background context so the reconnect outlives the settings window.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		status, err := conn.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("failed to get service status: %v", err)
			return
		}
		if status.Status == string(internal.StatusConnected) {
			if _, err = conn.Down(ctx, &proto.DownRequest{}); err != nil {
				log.Errorf("failed to stop service: %v", err)
			}
			// TODO: wait for the service to be idle before calling Up, or use a fresh connection
			if _, err = conn.Up(ctx, &proto.UpRequest{}); err != nil {
				log.Errorf("failed to start service: %v", err)
			}
		}
	}()

	return nil
}

func (s *serviceClient) getSettingsForm() fyne.CanvasObject {
	connectionForm := s.getConnectionForm()
	networkForm := s.getNetworkForm()
	sshForm := s.getSSHForm()
	tabs := container.NewAppTabs(
		container.NewTabItem("Connection", connectionForm),
		container.NewTabItem("Network", networkForm),
		container.NewTabItem("SSH", sshForm),
	)
	saveButton := widget.NewButtonWithIcon("Save", theme.ConfirmIcon(), s.saveSettings)
	saveButton.Importance = widget.HighImportance
	cancelButton := widget.NewButtonWithIcon("Cancel", theme.CancelIcon(), func() {
		s.wSettings.Close()
	})
	buttonContainer := container.NewHBox(
		layout.NewSpacer(),
		cancelButton,
		saveButton,
	)
	return container.NewBorder(nil, buttonContainer, nil, nil, tabs)
}

func (s *serviceClient) getNetworkForm() *widget.Form {
	return &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Network Monitor", Widget: s.sNetworkMonitor},
			{Text: "Disable DNS", Widget: s.sDisableDNS},
			{Text: "Disable Client Routes", Widget: s.sDisableClientRoutes},
			{Text: "Disable Server Routes", Widget: s.sDisableServerRoutes},
			{Text: "Disable IPv6", Widget: s.sDisableIPv6},
			{Text: "Disable LAN Access", Widget: s.sBlockLANAccess},
		},
	}
}

func (s *serviceClient) getSSHForm() *widget.Form {
	return &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Enable SSH Root Login", Widget: s.sEnableSSHRoot},
			{Text: "Enable SSH SFTP", Widget: s.sEnableSSHSFTP},
			{Text: "Enable SSH Local Port Forwarding", Widget: s.sEnableSSHLocalPortForward},
			{Text: "Enable SSH Remote Port Forwarding", Widget: s.sEnableSSHRemotePortForward},
			{Text: "Disable SSH Authentication", Widget: s.sDisableSSHAuth},
			{Text: "JWT Cache TTL (seconds, 0=disabled)", Widget: s.iSSHJWTCacheTTL},
		},
	}
}

func (s *serviceClient) hasSSHChanges() bool {
	currentSSHJWTCacheTTL := s.sshJWTCacheTTL
	if text := strings.TrimSpace(s.iSSHJWTCacheTTL.Text); text != "" {
		val, err := strconv.Atoi(text)
		if err != nil {
			return true
		}
		currentSSHJWTCacheTTL = val
	}

	return s.enableSSHRoot != s.sEnableSSHRoot.Checked ||
		s.enableSSHSFTP != s.sEnableSSHSFTP.Checked ||
		s.enableSSHLocalPortForward != s.sEnableSSHLocalPortForward.Checked ||
		s.enableSSHRemotePortForward != s.sEnableSSHRemotePortForward.Checked ||
		s.disableSSHAuth != s.sDisableSSHAuth.Checked ||
		s.sshJWTCacheTTL != currentSSHJWTCacheTTL
}

func (s *serviceClient) login(ctx context.Context, openURL bool) (*proto.LoginResponse, error) {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return nil, fmt.Errorf("get daemon client: %w", err)
	}

	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	currUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}

	handle := activeProf.ID.String()

	loginReq := &proto.LoginRequest{
		IsUnixDesktopClient: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
		ProfileName:         &handle,
		Username:            &currUser.Username,
	}

	profileState, err := s.profileManager.GetProfileState(activeProf.ID)
	if err != nil {
		log.Debugf("failed to get profile state for login hint: %v", err)
	} else if profileState.Email != "" {
		loginReq.Hint = &profileState.Email
	}

	loginResp, err := conn.Login(ctx, loginReq)
	if err != nil {
		return nil, fmt.Errorf("login to management: %w", err)
	}

	if loginResp.NeedsSSOLogin && openURL {
		if err = s.handleSSOLogin(ctx, loginResp, conn); err != nil {
			return nil, fmt.Errorf("SSO login: %w", err)
		}
	}

	return loginResp, nil
}

func (s *serviceClient) handleSSOLogin(ctx context.Context, loginResp *proto.LoginResponse, conn proto.DaemonServiceClient) error {
	if err := openURL(loginResp.VerificationURIComplete); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}

	resp, err := conn.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
	if err != nil {
		return fmt.Errorf("wait for SSO login: %w", err)
	}

	if resp.Email != "" {
		if err := s.profileManager.SetActiveProfileState(&profilemanager.ProfileState{
			Email: resp.Email,
		}); err != nil {
			log.Debugf("failed to set profile state: %v", err)
		} else {
			s.mProfile.refresh()
		}
	}

	return nil
}

func (s *serviceClient) menuUpClick(ctx context.Context) error {
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		systray.SetTemplateIcon(iconErrorMacOS, s.icError)
		return fmt.Errorf("get daemon client: %w", err)
	}

	_, err = s.login(ctx, true)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	status, err := conn.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if status.Status == string(internal.StatusConnected) {
		return nil
	}

	if _, err := s.conn.Up(s.ctx, &proto.UpRequest{}); err != nil {
		return fmt.Errorf("start connection: %w", err)
	}

	return nil
}

func (s *serviceClient) menuDownClick() error {
	systray.SetTemplateIcon(iconConnectingMacOS, s.icConnecting)
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		return fmt.Errorf("get daemon client: %w", err)
	}

	status, err := conn.Status(s.ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if status.Status != string(internal.StatusConnected) && status.Status != string(internal.StatusConnecting) {
		return nil
	}

	if _, err := conn.Down(s.ctx, &proto.DownRequest{}); err != nil {
		return fmt.Errorf("stop connection: %w", err)
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
				s.notifier.Send("Error", "Connection to service lost")
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
		case status.Status == string(internal.StatusConnected) && !s.connected:
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
			if s.networksEnabled {
				s.mNetworks.Enable()
				s.mExitNode.Enable()
			}
			s.startExitNodeRefresh()
			systrayIconState = true
		case status.Status == string(internal.StatusConnecting):
			s.setConnectingStatus()
		case status.Status != string(internal.StatusConnected) && s.mUp.Disabled():
			s.setDisconnectedStatus()
			systrayIconState = false
		}

		// if the daemon version changed (e.g. after a successful update), reset the update indication
		if s.daemonVersion != status.DaemonVersion {
			if s.daemonVersion != "" {
				s.mUpdate.Hide()
				s.isUpdateIconActive = false
			}
			s.daemonVersion = status.DaemonVersion
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
	s.cancelExitNodeRetry()
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
		serviceClient:        s,
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
	// Seed the transition cache to match the actual default menu
	// state (visible / enabled). Without this, the first
	// checkAndUpdateFeatures tick that observes DisableProfiles=true
	// is a no-op (cache zero-value == desired-false) and the menu
	// never gets hidden — symptom: MDM enforces the kill switch but
	// the profile menu stays clickable.
	s.profilesEnabled = true

	systray.AddSeparator()
	s.mUp = systray.AddMenuItem("Connect", "Connect")
	s.mDown = systray.AddMenuItem("Disconnect", "Disconnect")
	s.mDown.Disable()
	systray.AddSeparator()

	s.mSettings = systray.AddMenuItem("Settings", disabledMenuDescr)
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

	// Disable profile menu if profiles are disabled by daemon.
	// DisableUpdateSettings is enforced at the daemon's SetConfig /
	// Login gates, not by hiding the UI — so the Settings menu (and
	// its Advanced Settings submenu, which has its own kill switch)
	// stays visible and the user can still inspect current values.
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		// Continue with default behavior if features can't be retrieved
	} else if features != nil && features.DisableProfiles {
		s.mProfile.setEnabled(false)
		s.profilesEnabled = false
	}

	s.exitNodeMu.Lock()
	s.mExitNode = systray.AddMenuItem("Exit Node", disabledMenuDescr)
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

	// Features (DisableProfiles, DisableUpdateSettings, DisableNetworks,
	// ...) only change in two ways: at service install time (CLI flag,
	// static) and at MDM ticker diff time. The daemon already publishes
	// a SystemEvent{type=config_changed} on every MDM-driven engine
	// restart, so the UI no longer needs to poll GetFeatures every 2 s.
	// A single fetch at startup covers the static CLI-flag case; the
	// event handler below covers MDM transitions. updateStatus stays in
	// the 2 s loop because connection / peer state genuinely change
	// continuously and have no event yet.
	s.checkAndUpdateFeatures()
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

	s.eventManager = event.NewManager(s.notifier, s.addr)
	s.eventManager.SetNotificationsEnabled(s.mNotifications.Checked())
	s.eventManager.AddHandler(func(event *proto.SystemEvent) {
		if event.Category == proto.SystemEvent_SYSTEM {
			s.updateExitNodes()
		}
	})
	s.eventManager.AddHandler(func(event *proto.SystemEvent) {
		// todo use new Category
		if windowAction, ok := event.Metadata["progress_window"]; ok {
			targetVersion, ok := event.Metadata["version"]
			if !ok {
				targetVersion = "unknown"
			}
			log.Debugf("window action: %v", windowAction)
			if windowAction == "show" {
				if s.updateContextCancel != nil {
					s.updateContextCancel()
					s.updateContextCancel = nil
				}

				subCtx, cancel := context.WithCancel(s.ctx)
				go s.eventHandler.runSelfCommand(subCtx, "update", "--update-version", targetVersion)
				s.updateContextCancel = cancel
			}
		}
	})
	s.eventManager.AddHandler(func(event *proto.SystemEvent) {
		if newVersion, ok := event.Metadata["new_version_available"]; ok {
			_, enforced := event.Metadata["enforced"]
			log.Infof("received new_version_available event: version=%s enforced=%v", newVersion, enforced)
			s.onUpdateAvailable(newVersion, enforced)
		}
	})
	s.eventManager.AddHandler(func(event *proto.SystemEvent) {
		// Daemon emits a config_changed event after every engine spawn
		// (Server.Start, Server.Up, MDM ticker restart). Re-sync the
		// tray submenu checkboxes from the fresh daemon-side config so
		// the user does not have to restart the tray to see CLI- or
		// MDM-driven changes.
		if event.Category == proto.SystemEvent_SYSTEM && event.Metadata["type"] == "config_changed" {
			log.Infof("config_changed event received (source=%s); refreshing settings + features", event.Metadata["source"])
			s.loadSettings()
			// MDM-driven feature kill switches (DisableProfiles /
			// DisableUpdateSettings / DisableNetworks) ride the same
			// config_changed signal because the daemon re-applies its
			// MDM policy on every engine spawn. Pull them in here so
			// the UI is up to date without a periodic GetFeatures poll.
			s.checkAndUpdateFeatures()
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
	s.connLock.Lock()
	defer s.connLock.Unlock()
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

// checkAndUpdateFeatures checks the current features and updates the UI accordingly
func (s *serviceClient) checkAndUpdateFeatures() {
	features, err := s.getFeatures()
	if err != nil {
		log.Errorf("failed to get features from daemon: %v", err)
		return
	}

	s.updateIndicationLock.Lock()
	defer s.updateIndicationLock.Unlock()

	// DisableUpdateSettings is enforced server-side by the daemon gates
	// on SetConfig + Login: any attempt to mutate config from UI or
	// CLI is rejected at that layer. The UI deliberately keeps the
	// Settings menu visible so the user can still inspect current
	// values — read-only by virtue of the daemon refusing edits.

	// Update profile menu based on current features
	if s.mProfile != nil {
		profilesEnabled := features == nil || !features.DisableProfiles
		if s.profilesEnabled != profilesEnabled {
			s.profilesEnabled = profilesEnabled
			s.mProfile.setEnabled(profilesEnabled)
		}
	}

	// Update networks and exit node menus based on current features.
	// `networksEnabled` is the bare feature flag (read elsewhere, e.g. at
	// connection-status transitions). `networksMenuEnabled` is the
	// transition-cached state actually applied to the menu items —
	// it folds in the connection state so a Connected client with the
	// kill switch off shows the menus active, and only flips on diff.
	s.networksEnabled = features == nil || !features.DisableNetworks
	desiredNetworksMenu := s.networksEnabled && s.connected
	if desiredNetworksMenu != s.networksMenuEnabled {
		s.networksMenuEnabled = desiredNetworksMenu
		if desiredNetworksMenu {
			s.mNetworks.Enable()
			s.mExitNode.Enable()
		} else {
			s.mNetworks.Disable()
			s.mExitNode.Disable()
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

// disableAutoConnectFromDaemon returns true when the daemon reports
// the active profile has DisableAutoConnect=true. Used by the
// --quick-actions startup path to suppress the on-boot popup when the
// user (or an MDM admin) opted out of auto-connecting; both cases
// converge on the same Config field because applyMDMPolicy writes the
// policy value into it. Returns false on any RPC / lookup failure so a
// daemon hiccup does not silently swallow the popup.
func (s *serviceClient) disableAutoConnectFromDaemon() bool {
	activeProf, err := s.profileManager.GetActiveProfile()
	if err != nil {
		log.Warnf("disableAutoConnectFromDaemon: get active profile: %v", err)
		return false
	}
	currUser, err := user.Current()
	if err != nil {
		log.Warnf("disableAutoConnectFromDaemon: get current user: %v", err)
		return false
	}
	conn, err := s.getSrvClient(failFastTimeout)
	if err != nil {
		log.Warnf("disableAutoConnectFromDaemon: get daemon client: %v", err)
		return false
	}
	srvCfg, err := conn.GetConfig(s.ctx, &proto.GetConfigRequest{
		ProfileName: activeProf.ID.String(),
		Username:    currUser.Username,
	})
	if err != nil {
		log.Warnf("disableAutoConnectFromDaemon: GetConfig RPC: %v", err)
		return false
	}
	return srvCfg.GetDisableAutoConnect()
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
		ProfileName: activeProf.ID.String(),
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
	s.disableIPv6 = cfg.DisableIPv6
	s.blockLANAccess = cfg.BlockLANAccess

	if cfg.EnableSSHRoot != nil {
		s.enableSSHRoot = *cfg.EnableSSHRoot
	}
	if cfg.EnableSSHSFTP != nil {
		s.enableSSHSFTP = *cfg.EnableSSHSFTP
	}
	if cfg.EnableSSHLocalPortForwarding != nil {
		s.enableSSHLocalPortForward = *cfg.EnableSSHLocalPortForwarding
	}
	if cfg.EnableSSHRemotePortForwarding != nil {
		s.enableSSHRemotePortForward = *cfg.EnableSSHRemotePortForwarding
	}
	if cfg.DisableSSHAuth != nil {
		s.disableSSHAuth = *cfg.DisableSSHAuth
	}
	if cfg.SSHJWTCacheTTL != nil {
		s.sshJWTCacheTTL = *cfg.SSHJWTCacheTTL
	}

	if s.showAdvancedSettings {
		s.iMngURL.SetText(s.managementURL)
		// PSK is rendered with an empty Text and a hint via the
		// placeholder so the eye toggle never reveals literal asterisks
		// (the daemon returns the "**********" sentinel — writing that
		// into a PasswordEntry would surface the literal sentinel when
		// the user unmasks the field). The placeholder communicates the
		// configured / MDM-managed state without exposing any value.
		s.iPreSharedKey.SetText("")
		s.iPreSharedKey.SetPlaceHolder(preSharedKeyPlaceholder(srvCfg))
		s.iInterfaceName.SetText(cfg.WgIface)
		s.iInterfacePort.SetText(strconv.Itoa(cfg.WgPort))
		if cfg.MTU != 0 {
			s.iMTU.SetText(strconv.Itoa(int(cfg.MTU)))
		} else {
			s.iMTU.SetText("")
			s.iMTU.SetPlaceHolder(strconv.Itoa(int(iface.DefaultMTU)))
		}
		s.sRosenpassPermissive.SetChecked(cfg.RosenpassPermissive)
		// Re-baseline the enabled state on every refresh: when Rosenpass
		// is on the checkbox is editable, when it's off the field is
		// inert. Without an explicit Enable() here the control stays
		// stuck disabled after a previous refresh (or an MDM unlock) had
		// turned it off — applyMDMLocksToSettingsForm below adds the
		// MDM lock on top of this baseline.
		if cfg.RosenpassEnabled {
			s.sRosenpassPermissive.Enable()
		} else {
			s.sRosenpassPermissive.Disable()
		}
		s.sNetworkMonitor.SetChecked(*cfg.NetworkMonitor)
		s.sDisableDNS.SetChecked(cfg.DisableDNS)
		s.sDisableClientRoutes.SetChecked(cfg.DisableClientRoutes)
		s.sDisableServerRoutes.SetChecked(cfg.DisableServerRoutes)
		s.sDisableIPv6.SetChecked(cfg.DisableIPv6)
		s.sBlockLANAccess.SetChecked(cfg.BlockLANAccess)
		if cfg.EnableSSHRoot != nil {
			s.sEnableSSHRoot.SetChecked(*cfg.EnableSSHRoot)
		}
		if cfg.EnableSSHSFTP != nil {
			s.sEnableSSHSFTP.SetChecked(*cfg.EnableSSHSFTP)
		}
		if cfg.EnableSSHLocalPortForwarding != nil {
			s.sEnableSSHLocalPortForward.SetChecked(*cfg.EnableSSHLocalPortForwarding)
		}
		if cfg.EnableSSHRemotePortForwarding != nil {
			s.sEnableSSHRemotePortForward.SetChecked(*cfg.EnableSSHRemotePortForwarding)
		}
		if cfg.DisableSSHAuth != nil {
			s.sDisableSSHAuth.SetChecked(*cfg.DisableSSHAuth)
		}
		if cfg.SSHJWTCacheTTL != nil {
			s.iSSHJWTCacheTTL.SetText(strconv.Itoa(*cfg.SSHJWTCacheTTL))
		}
	}

	// MDM locks must run before the mNotifications-nil early return:
	// the Settings window is rendered by a separate UI process launched
	// with --settings (see handleAdvancedSettingsClick), and that child
	// process does NOT run onReady — so its mNotifications is nil and
	// the early return below skipped the lock pass entirely.
	s.applyMDMLocks(srvCfg.MDMManagedFields)

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
	if cfg.WireguardPort >= 0 && cfg.WireguardPort <= 65535 {
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
	config.DisableIPv6 = cfg.DisableIpv6
	config.BlockLANAccess = cfg.BlockLanAccess

	config.EnableSSHRoot = &cfg.EnableSSHRoot
	config.EnableSSHSFTP = &cfg.EnableSSHSFTP
	config.EnableSSHLocalPortForwarding = &cfg.EnableSSHLocalPortForwarding
	config.EnableSSHRemotePortForwarding = &cfg.EnableSSHRemotePortForwarding
	config.DisableSSHAuth = &cfg.DisableSSHAuth

	ttl := int(cfg.SshJWTCacheTTL)
	config.SSHJWTCacheTTL = &ttl

	return &config
}

func (s *serviceClient) onUpdateAvailable(newVersion string, enforced bool) {
	s.updateIndicationLock.Lock()
	defer s.updateIndicationLock.Unlock()

	s.isEnforcedUpdate = enforced
	if enforced {
		s.mUpdate.SetTitle("Install version " + newVersion)
	} else {
		s.lastNotifiedVersion = ""
		s.mUpdate.SetTitle("Download latest version")
	}

	s.mUpdate.Show()
	s.isUpdateIconActive = true

	if s.connected {
		systray.SetTemplateIcon(iconUpdateConnectedMacOS, s.icUpdateConnected)
	} else {
		systray.SetTemplateIcon(iconUpdateDisconnectedMacOS, s.icUpdateDisconnected)
	}

	if enforced && s.lastNotifiedVersion != newVersion {
		s.lastNotifiedVersion = newVersion
		s.notifier.Send("Update available", "A new version "+newVersion+" is ready to install")
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
		ProfileName: activeProf.ID.String(),
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
	s.applyMDMLocks(cfg.MDMManagedFields)
}

// applyMDMLocks disables and badges any tray submenu item or settings-
// form widget whose underlying field is enforced by the active MDM
// policy. Called from loadSettings (submenu refresh) and from
// getSrvConfig (settings-window refresh). Locked items keep their value
// already set by the surrounding refresh code — this routine only
// flips the enabled state and the title suffix, never the value.
func (s *serviceClient) applyMDMLocks(managed []string) {
	set := make(map[string]bool, len(managed))
	for _, k := range managed {
		set[k] = true
	}
	s.mdmManagedFields = set
	if len(managed) > 0 {
		log.Infof("MDM-managed UI fields: %v", managed)
	}

	type submenuTarget struct {
		item  *systray.MenuItem
		title string
		key   string
	}
	for _, t := range []submenuTarget{
		{s.mAllowSSH, "Allow SSH", mdm.KeyAllowServerSSH},
		{s.mAutoConnect, "Connect on Startup", mdm.KeyDisableAutoConnect},
		{s.mEnableRosenpass, "Enable Quantum-Resistance", mdm.KeyRosenpassEnabled},
		{s.mBlockInbound, "Block Inbound Connections", mdm.KeyBlockInbound},
	} {
		if t.item == nil {
			continue
		}
		if set[t.key] {
			t.item.SetTitle(t.title + " (MDM)")
			t.item.Disable()
		} else {
			t.item.SetTitle(t.title)
			t.item.Enable()
		}
	}

	s.applyMDMLocksToSettingsForm(set)
}

// preSharedKeyPlaceholder returns the hint string shown in the PSK
// Entry's placeholder slot. The placeholder is the only signal the
// user gets that a PSK is configured, because the entry's Text is
// forced to empty to keep the password reveal toggle from leaking
// the daemon-returned "**********" redaction sentinel. Returns "" if
// no PSK is present, "MDM-managed" if the key is enforced by MDM,
// and "configured" otherwise.
func preSharedKeyPlaceholder(cfg *proto.GetConfigResponse) string {
	if cfg == nil || cfg.PreSharedKey == "" {
		return ""
	}
	for _, k := range cfg.MDMManagedFields {
		if k == mdm.KeyPreSharedKey {
			return "MDM-managed"
		}
	}
	return "configured"
}

// applyMDMLocksToSettingsForm disables the per-field input widgets in
// the advanced Settings window when the corresponding MDM key is set.
// For plain-text entries (Management URL, Interface Port) the visible
// value is suffixed with " (MDM)" so the user sees the lock indicator
// inline; for the password entry the suffix is skipped (a password
// widget renders every char as a dot and the indicator would not be
// readable). The widgets are created lazily by showSettingsUI, so
// guard each ref against nil.
func (s *serviceClient) applyMDMLocksToSettingsForm(set map[string]bool) {
	type entryTarget struct {
		entry     *widget.Entry
		key       string
		inlineTag bool
	}
	for _, t := range []entryTarget{
		{s.iMngURL, mdm.KeyManagementURL, true},
		{s.iPreSharedKey, mdm.KeyPreSharedKey, false},
		{s.iInterfacePort, mdm.KeyWireguardPort, true},
	} {
		if t.entry == nil {
			continue
		}
		if set[t.key] {
			if t.inlineTag && t.entry.Text != "" && !strings.HasSuffix(t.entry.Text, mdmFieldSuffix) {
				t.entry.SetText(t.entry.Text + mdmFieldSuffix)
			}
			t.entry.Disable()
		} else {
			if t.inlineTag {
				t.entry.SetText(strings.TrimSuffix(t.entry.Text, mdmFieldSuffix))
			}
			t.entry.Enable()
		}
	}
	type checkTarget struct {
		check *widget.Check
		key   string
	}
	for _, t := range []checkTarget{
		{s.sDisableClientRoutes, mdm.KeyDisableClientRoutes},
		{s.sDisableServerRoutes, mdm.KeyDisableServerRoutes},
	} {
		if t.check == nil {
			continue
		}
		if set[t.key] {
			t.check.Disable()
		} else {
			t.check.Enable()
		}
	}
	if s.sRosenpassPermissive != nil && set[mdm.KeyRosenpassPermissive] {
		// MDM lock layered on top of the Rosenpass-on/off baseline
		// applied by getSrvConfig. No Enable() branch here: when the
		// MDM key is removed, the next getSrvConfig refresh re-baselines
		// the control on cfg.RosenpassEnabled and brings it back if
		// Rosenpass is on.
		s.sRosenpassPermissive.Disable()
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
		ProfileName:           activeProf.ID.String(),
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

		resp, err := s.login(ctx, false)
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

		_, err = conn.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: resp.UserCode})
		if err != nil {
			log.Errorf("Waiting sso login failed with: %v", err)
			label.SetText("Waiting login failed, please create \na debug bundle in the settings and contact support.")
			return
		}

		label.SetText("Re-authentication successful.\nReconnecting")
		status, err := conn.Status(ctx, &proto.StatusRequest{})
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

		_, err = conn.Up(ctx, &proto.UpRequest{})
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
	if browser := os.Getenv("BROWSER"); browser != "" {
		return exec.Command(browser, url).Start()
	}

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
