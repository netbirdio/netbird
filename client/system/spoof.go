package system

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const SpoofDirEnv = "NB_SPOOF_DIR"

type SpoofNetworkAddress struct {
	NetIP string `json:"netIP"`
	Mac   string `json:"mac"`
}

type SpoofEnvironment struct {
	Cloud    *string `json:"cloud,omitempty"`
	Platform *string `json:"platform,omitempty"`
}

type SpoofFlags struct {
	RosenpassEnabled              *bool `json:"rosenpassEnabled,omitempty"`
	RosenpassPermissive           *bool `json:"rosenpassPermissive,omitempty"`
	ServerSSHAllowed              *bool `json:"serverSSHAllowed,omitempty"`
	RemoteJobsAllowed             *bool `json:"remoteJobsAllowed,omitempty"`
	DisableClientRoutes           *bool `json:"disableClientRoutes,omitempty"`
	DisableServerRoutes           *bool `json:"disableServerRoutes,omitempty"`
	DisableDNS                    *bool `json:"disableDNS,omitempty"`
	DisableFirewall               *bool `json:"disableFirewall,omitempty"`
	BlockLANAccess                *bool `json:"blockLANAccess,omitempty"`
	BlockInbound                  *bool `json:"blockInbound,omitempty"`
	DisableIPv6                   *bool `json:"disableIPv6,omitempty"`
	EnableSSHRoot                 *bool `json:"enableSSHRoot,omitempty"`
	EnableSSHSFTP                 *bool `json:"enableSSHSFTP,omitempty"`
	EnableSSHLocalPortForwarding  *bool `json:"enableSSHLocalPortForwarding,omitempty"`
	EnableSSHRemotePortForwarding *bool `json:"enableSSHRemotePortForwarding,omitempty"`
	DisableSSHAuth                *bool `json:"disableSSHAuth,omitempty"`
}

type SpoofFlagsSnapshot struct {
	RosenpassEnabled              bool `json:"rosenpassEnabled"`
	RosenpassPermissive           bool `json:"rosenpassPermissive"`
	ServerSSHAllowed              bool `json:"serverSSHAllowed"`
	RemoteJobsAllowed             bool `json:"remoteJobsAllowed"`
	DisableClientRoutes           bool `json:"disableClientRoutes"`
	DisableServerRoutes           bool `json:"disableServerRoutes"`
	DisableDNS                    bool `json:"disableDNS"`
	DisableFirewall               bool `json:"disableFirewall"`
	BlockLANAccess                bool `json:"blockLANAccess"`
	BlockInbound                  bool `json:"blockInbound"`
	DisableIPv6                   bool `json:"disableIPv6"`
	EnableSSHRoot                 bool `json:"enableSSHRoot"`
	EnableSSHSFTP                 bool `json:"enableSSHSFTP"`
	EnableSSHLocalPortForwarding  bool `json:"enableSSHLocalPortForwarding"`
	EnableSSHRemotePortForwarding bool `json:"enableSSHRemotePortForwarding"`
	DisableSSHAuth                bool `json:"disableSSHAuth"`
}

type SpoofPostureChecks struct {
	All          *bool           `json:"all,omitempty"`
	AllFiles     *bool           `json:"allFiles,omitempty"`
	AllProcesses *bool           `json:"allProcesses,omitempty"`
	Files        map[string]bool `json:"files,omitempty"`
	Processes    map[string]bool `json:"processes,omitempty"`
}

type PostureCheckRecord struct {
	Timestamp      string   `json:"timestamp"`
	RequestedPaths []string `json:"requestedPaths"`
	Real           []File   `json:"real"`
	Reported       []File   `json:"reported"`
}

type SpoofConfig struct {
	Hostname           *string               `json:"hostname,omitempty"`
	GoOS               *string               `json:"goOS,omitempty"`
	Kernel             *string               `json:"kernel,omitempty"`
	KernelVersion      *string               `json:"kernelVersion,omitempty"`
	Platform           *string               `json:"platform,omitempty"`
	OS                 *string               `json:"os,omitempty"`
	OSVersion          *string               `json:"osVersion,omitempty"`
	NetbirdVersion     *string               `json:"netbirdVersion,omitempty"`
	UIVersion          *string               `json:"uiVersion,omitempty"`
	SystemSerialNumber *string               `json:"systemSerialNumber,omitempty"`
	SystemProductName  *string               `json:"systemProductName,omitempty"`
	SystemManufacturer *string               `json:"systemManufacturer,omitempty"`
	Environment        *SpoofEnvironment     `json:"environment,omitempty"`
	NetworkAddresses   []SpoofNetworkAddress `json:"networkAddresses,omitempty"`

	// Flags (nested under "flags" or top-level)
	Flags                         *SpoofFlags `json:"flags,omitempty"`
	RosenpassEnabled              *bool       `json:"rosenpassEnabled,omitempty"`
	RosenpassPermissive           *bool       `json:"rosenpassPermissive,omitempty"`
	ServerSSHAllowed              *bool       `json:"serverSSHAllowed,omitempty"`
	RemoteJobsAllowed             *bool       `json:"remoteJobsAllowed,omitempty"`
	DisableClientRoutes           *bool       `json:"disableClientRoutes,omitempty"`
	DisableServerRoutes           *bool       `json:"disableServerRoutes,omitempty"`
	DisableDNS                    *bool       `json:"disableDNS,omitempty"`
	DisableFirewall               *bool       `json:"disableFirewall,omitempty"`
	BlockLANAccess                *bool       `json:"blockLANAccess,omitempty"`
	BlockInbound                  *bool       `json:"blockInbound,omitempty"`
	DisableIPv6                   *bool       `json:"disableIPv6,omitempty"`
	EnableSSHRoot                 *bool       `json:"enableSSHRoot,omitempty"`
	EnableSSHSFTP                 *bool       `json:"enableSSHSFTP,omitempty"`
	EnableSSHLocalPortForwarding  *bool       `json:"enableSSHLocalPortForwarding,omitempty"`
	EnableSSHRemotePortForwarding *bool       `json:"enableSSHRemotePortForwarding,omitempty"`
	DisableSSHAuth                *bool       `json:"disableSSHAuth,omitempty"`

	// Posture Checks (nested under "postureChecks" or top-level)
	PostureChecks            *SpoofPostureChecks `json:"postureChecks,omitempty"`
	PostureCheckAll          *bool               `json:"postureCheckAll,omitempty"`
	PostureCheckAllFiles     *bool               `json:"postureCheckAllFiles,omitempty"`
	PostureCheckAllProcesses *bool               `json:"postureCheckAllProcesses,omitempty"`
	PostureCheckFiles        map[string]bool     `json:"postureCheckFiles,omitempty"`
	PostureCheckProcesses    map[string]bool     `json:"postureCheckProcesses,omitempty"`
}

type InfoSnapshot struct {
	Hostname           string                `json:"hostname"`
	GoOS               string                `json:"goOS"`
	Kernel             string                `json:"kernel"`
	KernelVersion      string                `json:"kernelVersion"`
	Platform           string                `json:"platform"`
	OS                 string                `json:"os"`
	OSVersion          string                `json:"osVersion"`
	NetbirdVersion     string                `json:"netbirdVersion"`
	UIVersion          string                `json:"uiVersion"`
	SystemSerialNumber string                `json:"systemSerialNumber"`
	SystemProductName  string                `json:"systemProductName"`
	SystemManufacturer string                `json:"systemManufacturer"`
	Environment        SpoofEnvironment      `json:"environment"`
	NetworkAddresses   []SpoofNetworkAddress `json:"networkAddresses"`
	Files              []File                `json:"files,omitempty"`
	Flags              SpoofFlagsSnapshot    `json:"flags"`
}

var (
	spoofMu      sync.RWMutex
	spoofDir     string
	spoofConfig  *SpoofConfig
	spoofLastMod time.Time
)

// SpoofEnabled reports whether system info spoofing is active.
func SpoofEnabled() bool {
	return getSpoofConfig() != nil || getSpoofDir() != ""
}

func getSpoofDir() string {
	return os.Getenv(SpoofDirEnv)
}

func getSpoofConfig() *SpoofConfig {
	dir := getSpoofDir()
	if dir == "" {
		return nil
	}

	spoofMu.Lock()
	defer spoofMu.Unlock()

	if dir != spoofDir {
		spoofDir = dir
		spoofConfig = nil
		spoofLastMod = time.Time{}
	}

	overridesPath := filepath.Join(dir, "overrides.json")
	fi, err := os.Stat(overridesPath)
	if err != nil {
		if os.IsNotExist(err) {
			spoofConfig = nil
		}
		return spoofConfig
	}

	if spoofConfig == nil || fi.ModTime().After(spoofLastMod) {
		cfg, err := loadOverrides(overridesPath)
		if err != nil {
			log.Warnf("spoof: failed to load overrides from %s: %v", overridesPath, err)
		} else {
			spoofConfig = cfg
			spoofLastMod = fi.ModTime()
			log.Infof("spoof: loaded overrides from %s", overridesPath)
		}
	}

	return spoofConfig
}

func loadOverrides(path string) (*SpoofConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg SpoofConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func infoToSnapshot(info *Info) InfoSnapshot {
	snap := InfoSnapshot{
		Hostname:           info.Hostname,
		GoOS:               info.GoOS,
		Kernel:             info.Kernel,
		KernelVersion:      info.KernelVersion,
		Platform:           info.Platform,
		OS:                 info.OS,
		OSVersion:          info.OSVersion,
		NetbirdVersion:     info.NetbirdVersion,
		UIVersion:          info.UIVersion,
		SystemSerialNumber: info.SystemSerialNumber,
		SystemProductName:  info.SystemProductName,
		SystemManufacturer: info.SystemManufacturer,
		Environment: SpoofEnvironment{
			Cloud:    &info.Environment.Cloud,
			Platform: &info.Environment.Platform,
		},
		Files: make([]File, len(info.Files)),
		Flags: SpoofFlagsSnapshot{
			RosenpassEnabled:              info.RosenpassEnabled,
			RosenpassPermissive:           info.RosenpassPermissive,
			ServerSSHAllowed:              info.ServerSSHAllowed,
			RemoteJobsAllowed:             info.RemoteJobsAllowed,
			DisableClientRoutes:           info.DisableClientRoutes,
			DisableServerRoutes:           info.DisableServerRoutes,
			DisableDNS:                    info.DisableDNS,
			DisableFirewall:               info.DisableFirewall,
			BlockLANAccess:                info.BlockLANAccess,
			BlockInbound:                  info.BlockInbound,
			DisableIPv6:                   info.DisableIPv6,
			EnableSSHRoot:                 info.EnableSSHRoot,
			EnableSSHSFTP:                 info.EnableSSHSFTP,
			EnableSSHLocalPortForwarding:  info.EnableSSHLocalPortForwarding,
			EnableSSHRemotePortForwarding: info.EnableSSHRemotePortForwarding,
			DisableSSHAuth:                info.DisableSSHAuth,
		},
	}

	copy(snap.Files, info.Files)

	for _, addr := range info.NetworkAddresses {
		snap.NetworkAddresses = append(snap.NetworkAddresses, SpoofNetworkAddress{
			NetIP: addr.NetIP.String(),
			Mac:   addr.Mac,
		})
	}

	return snap
}

func saveSnapshot(snap InfoSnapshot, path string) {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		log.Warnf("spoof: failed to marshal snapshot: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Warnf("spoof: failed to create directory for %s: %v", path, err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Warnf("spoof: failed to write %s: %v", path, err)
	}
}

func getFlag(topLevel *bool, nested *SpoofFlags, getter func(*SpoofFlags) *bool) *bool {
	if topLevel != nil {
		return topLevel
	}
	if nested != nil {
		return getter(nested)
	}
	return nil
}

func applySpoofFlags(info *Info) {
	dir := getSpoofDir()
	if dir == "" {
		return
	}
	cfg := getSpoofConfig()
	if cfg == nil {
		return
	}

	var nested *SpoofFlags
	if cfg.Flags != nil {
		nested = cfg.Flags
	}

	if val := getFlag(cfg.RosenpassEnabled, nested, func(f *SpoofFlags) *bool { return f.RosenpassEnabled }); val != nil {
		info.RosenpassEnabled = *val
	}
	if val := getFlag(cfg.RosenpassPermissive, nested, func(f *SpoofFlags) *bool { return f.RosenpassPermissive }); val != nil {
		info.RosenpassPermissive = *val
	}
	if val := getFlag(cfg.ServerSSHAllowed, nested, func(f *SpoofFlags) *bool { return f.ServerSSHAllowed }); val != nil {
		info.ServerSSHAllowed = *val
	}
	if val := getFlag(cfg.RemoteJobsAllowed, nested, func(f *SpoofFlags) *bool { return f.RemoteJobsAllowed }); val != nil {
		info.RemoteJobsAllowed = *val
	}
	if val := getFlag(cfg.DisableClientRoutes, nested, func(f *SpoofFlags) *bool { return f.DisableClientRoutes }); val != nil {
		info.DisableClientRoutes = *val
	}
	if val := getFlag(cfg.DisableServerRoutes, nested, func(f *SpoofFlags) *bool { return f.DisableServerRoutes }); val != nil {
		info.DisableServerRoutes = *val
	}
	if val := getFlag(cfg.DisableDNS, nested, func(f *SpoofFlags) *bool { return f.DisableDNS }); val != nil {
		info.DisableDNS = *val
	}
	if val := getFlag(cfg.DisableFirewall, nested, func(f *SpoofFlags) *bool { return f.DisableFirewall }); val != nil {
		info.DisableFirewall = *val
	}
	if val := getFlag(cfg.BlockLANAccess, nested, func(f *SpoofFlags) *bool { return f.BlockLANAccess }); val != nil {
		info.BlockLANAccess = *val
	}
	if val := getFlag(cfg.BlockInbound, nested, func(f *SpoofFlags) *bool { return f.BlockInbound }); val != nil {
		info.BlockInbound = *val
	}
	if val := getFlag(cfg.DisableIPv6, nested, func(f *SpoofFlags) *bool { return f.DisableIPv6 }); val != nil {
		info.DisableIPv6 = *val
	}
	if val := getFlag(cfg.EnableSSHRoot, nested, func(f *SpoofFlags) *bool { return f.EnableSSHRoot }); val != nil {
		info.EnableSSHRoot = *val
	}
	if val := getFlag(cfg.EnableSSHSFTP, nested, func(f *SpoofFlags) *bool { return f.EnableSSHSFTP }); val != nil {
		info.EnableSSHSFTP = *val
	}
	if val := getFlag(cfg.EnableSSHLocalPortForwarding, nested, func(f *SpoofFlags) *bool { return f.EnableSSHLocalPortForwarding }); val != nil {
		info.EnableSSHLocalPortForwarding = *val
	}
	if val := getFlag(cfg.EnableSSHRemotePortForwarding, nested, func(f *SpoofFlags) *bool { return f.EnableSSHRemotePortForwarding }); val != nil {
		info.EnableSSHRemotePortForwarding = *val
	}
	if val := getFlag(cfg.DisableSSHAuth, nested, func(f *SpoofFlags) *bool { return f.DisableSSHAuth }); val != nil {
		info.DisableSSHAuth = *val
	}

	saveSnapshot(infoToSnapshot(info), filepath.Join(dir, "reported.json"))
}

func applyPostureCheckOverrides(cfg *SpoofConfig, realFiles []File) []File {
	if len(realFiles) == 0 {
		return realFiles
	}

	var allFilesDefault *bool
	var allProcessesDefault *bool

	if cfg.PostureCheckAll != nil {
		allFilesDefault = cfg.PostureCheckAll
		allProcessesDefault = cfg.PostureCheckAll
	}
	if cfg.PostureCheckAllFiles != nil {
		allFilesDefault = cfg.PostureCheckAllFiles
	}
	if cfg.PostureCheckAllProcesses != nil {
		allProcessesDefault = cfg.PostureCheckAllProcesses
	}

	if cfg.PostureChecks != nil {
		if cfg.PostureChecks.All != nil {
			allFilesDefault = cfg.PostureChecks.All
			allProcessesDefault = cfg.PostureChecks.All
		}
		if cfg.PostureChecks.AllFiles != nil {
			allFilesDefault = cfg.PostureChecks.AllFiles
		}
		if cfg.PostureChecks.AllProcesses != nil {
			allProcessesDefault = cfg.PostureChecks.AllProcesses
		}
	}

	fileMap := make(map[string]bool)
	processMap := make(map[string]bool)

	for k, v := range cfg.PostureCheckFiles {
		fileMap[k] = v
	}
	for k, v := range cfg.PostureCheckProcesses {
		processMap[k] = v
	}
	if cfg.PostureChecks != nil {
		for k, v := range cfg.PostureChecks.Files {
			fileMap[k] = v
		}
		for k, v := range cfg.PostureChecks.Processes {
			processMap[k] = v
		}
	}

	spoofed := make([]File, len(realFiles))
	for i, f := range realFiles {
		item := f
		base := filepath.Base(f.Path)

		// 1. Files / Exist check
		if allFilesDefault != nil {
			item.Exist = *allFilesDefault
		}
		if val, ok := fileMap[base]; ok {
			item.Exist = val
		}
		if val, ok := fileMap[f.Path]; ok {
			item.Exist = val
		}

		// 2. Processes / ProcessIsRunning check
		if allProcessesDefault != nil {
			item.ProcessIsRunning = *allProcessesDefault
		}
		if val, ok := processMap[base]; ok {
			item.ProcessIsRunning = val
		}
		if val, ok := processMap[f.Path]; ok {
			item.ProcessIsRunning = val
		}

		spoofed[i] = item
	}

	return spoofed
}

func logPostureChecks(realFiles, reportedFiles []File) {
	dir := getSpoofDir()
	if dir == "" || len(realFiles) == 0 {
		return
	}

	now := time.Now().Format(time.RFC3339)
	paths := make([]string, len(realFiles))
	for i, f := range realFiles {
		paths[i] = f.Path
	}

	record := PostureCheckRecord{
		Timestamp:      now,
		RequestedPaths: paths,
		Real:           realFiles,
		Reported:       reportedFiles,
	}

	jsonPath := filepath.Join(dir, "posture_checks.json")
	if data, err := json.MarshalIndent(record, "", "  "); err == nil {
		if err := os.WriteFile(jsonPath, data, 0600); err != nil {
			log.Warnf("spoof: failed to write %s: %v", jsonPath, err)
		}
	}

	logPath := filepath.Join(dir, "posture_checks.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("[%s] received %d posture check(s):\n", now, len(realFiles)))
		for i, r := range realFiles {
			rep := reportedFiles[i]
			sb.WriteString(fmt.Sprintf("  - %s: real(exist=%t, running=%t) -> reported(exist=%t, running=%t)\n",
				r.Path, r.Exist, r.ProcessIsRunning, rep.Exist, rep.ProcessIsRunning))
		}
		if _, err := f.WriteString(sb.String()); err != nil {
			log.Warnf("spoof: failed to append to %s: %v", logPath, err)
		}
	}

	log.Infof("spoof: logged %d posture check(s) to %s", len(realFiles), jsonPath)
}

func applyOverrides(info *Info) *Info {
	cfg := getSpoofConfig()
	if cfg == nil {
		return info
	}

	spoofed := *info
	spoofed.NetworkAddresses = make([]NetworkAddress, len(info.NetworkAddresses))
	copy(spoofed.NetworkAddresses, info.NetworkAddresses)
	spoofed.Files = make([]File, len(info.Files))
	copy(spoofed.Files, info.Files)

	if cfg.Hostname != nil {
		spoofed.Hostname = *cfg.Hostname
	}
	if cfg.GoOS != nil {
		spoofed.GoOS = *cfg.GoOS
	}
	if cfg.Kernel != nil {
		spoofed.Kernel = *cfg.Kernel
	}
	if cfg.KernelVersion != nil {
		spoofed.KernelVersion = *cfg.KernelVersion
	}
	if cfg.Platform != nil {
		spoofed.Platform = *cfg.Platform
	}
	if cfg.OS != nil {
		spoofed.OS = *cfg.OS
	}
	if cfg.OSVersion != nil {
		spoofed.OSVersion = *cfg.OSVersion
	}
	if cfg.NetbirdVersion != nil {
		spoofed.NetbirdVersion = *cfg.NetbirdVersion
	}
	if cfg.UIVersion != nil {
		spoofed.UIVersion = *cfg.UIVersion
	}
	if cfg.SystemSerialNumber != nil {
		spoofed.SystemSerialNumber = *cfg.SystemSerialNumber
	}
	if cfg.SystemProductName != nil {
		spoofed.SystemProductName = *cfg.SystemProductName
	}
	if cfg.SystemManufacturer != nil {
		spoofed.SystemManufacturer = *cfg.SystemManufacturer
	}

	if cfg.Environment != nil {
		if cfg.Environment.Cloud != nil {
			spoofed.Environment.Cloud = *cfg.Environment.Cloud
		}
		if cfg.Environment.Platform != nil {
			spoofed.Environment.Platform = *cfg.Environment.Platform
		}
	}

	if len(cfg.NetworkAddresses) > 0 {
		spoofed.NetworkAddresses = make([]NetworkAddress, 0, len(cfg.NetworkAddresses))
		for _, addr := range cfg.NetworkAddresses {
			prefix, err := netip.ParsePrefix(addr.NetIP)
			if err != nil {
				log.Warnf("spoof: invalid network address %q: %v", addr.NetIP, err)
				continue
			}
			spoofed.NetworkAddresses = append(spoofed.NetworkAddresses, NetworkAddress{
				NetIP: prefix,
				Mac:   addr.Mac,
			})
		}
	}

	if len(info.Files) > 0 {
		spoofed.Files = applyPostureCheckOverrides(cfg, info.Files)
	}

	applySpoofFlags(&spoofed)

	return &spoofed
}

// applySpoofing saves real values, applies overrides, and saves reported values.
// Returns the (possibly modified) Info to use.
func applySpoofing(info *Info) *Info {
	dir := getSpoofDir()
	if dir == "" {
		return info
	}

	realSnap := infoToSnapshot(info)
	saveSnapshot(realSnap, filepath.Join(dir, "real.json"))

	spoofed := applyOverrides(info)

	if len(info.Files) > 0 {
		logPostureChecks(info.Files, spoofed.Files)
	}

	reportedSnap := infoToSnapshot(spoofed)
	saveSnapshot(reportedSnap, filepath.Join(dir, "reported.json"))

	return spoofed
}
