package system

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

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

type SpoofConfig struct {
	Hostname           *string              `json:"hostname,omitempty"`
	GoOS               *string              `json:"goOS,omitempty"`
	Kernel             *string              `json:"kernel,omitempty"`
	KernelVersion      *string              `json:"kernelVersion,omitempty"`
	Platform           *string              `json:"platform,omitempty"`
	OS                 *string              `json:"os,omitempty"`
	OSVersion          *string              `json:"osVersion,omitempty"`
	NetbirdVersion     *string              `json:"netbirdVersion,omitempty"`
	UIVersion          *string              `json:"uiVersion,omitempty"`
	SystemSerialNumber *string              `json:"systemSerialNumber,omitempty"`
	SystemProductName  *string              `json:"systemProductName,omitempty"`
	SystemManufacturer *string              `json:"systemManufacturer,omitempty"`
	Environment        *SpoofEnvironment    `json:"environment,omitempty"`
	NetworkAddresses   []SpoofNetworkAddress `json:"networkAddresses,omitempty"`
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
	NetworkAddresses   []SpoofNetworkAddress  `json:"networkAddresses"`
}

var (
	spoofOnce   sync.Once
	spoofDir    string
	spoofConfig *SpoofConfig
)

func initSpoof() {
	spoofOnce.Do(func() {
		spoofDir = os.Getenv(SpoofDirEnv)
		if spoofDir == "" {
			return
		}

		overridesPath := filepath.Join(spoofDir, "overrides.json")
		cfg, err := loadOverrides(overridesPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Infof("spoof: no overrides.json found at %s, will only write real.json", overridesPath)
			} else {
				log.Warnf("spoof: failed to load overrides from %s: %v", overridesPath, err)
			}
			return
		}
		spoofConfig = cfg
		log.Infof("spoof: loaded overrides from %s", overridesPath)
	})
}

func spoofEnabled() bool {
	initSpoof()
	return spoofDir != ""
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
	}

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

func applyOverrides(info *Info) *Info {
	if spoofConfig == nil {
		return info
	}

	spoofed := *info
	spoofed.NetworkAddresses = make([]NetworkAddress, len(info.NetworkAddresses))
	copy(spoofed.NetworkAddresses, info.NetworkAddresses)
	spoofed.Files = make([]File, len(info.Files))
	copy(spoofed.Files, info.Files)

	if spoofConfig.Hostname != nil {
		spoofed.Hostname = *spoofConfig.Hostname
	}
	if spoofConfig.GoOS != nil {
		spoofed.GoOS = *spoofConfig.GoOS
	}
	if spoofConfig.Kernel != nil {
		spoofed.Kernel = *spoofConfig.Kernel
	}
	if spoofConfig.KernelVersion != nil {
		spoofed.KernelVersion = *spoofConfig.KernelVersion
	}
	if spoofConfig.Platform != nil {
		spoofed.Platform = *spoofConfig.Platform
	}
	if spoofConfig.OS != nil {
		spoofed.OS = *spoofConfig.OS
	}
	if spoofConfig.OSVersion != nil {
		spoofed.OSVersion = *spoofConfig.OSVersion
	}
	if spoofConfig.NetbirdVersion != nil {
		spoofed.NetbirdVersion = *spoofConfig.NetbirdVersion
	}
	if spoofConfig.UIVersion != nil {
		spoofed.UIVersion = *spoofConfig.UIVersion
	}
	if spoofConfig.SystemSerialNumber != nil {
		spoofed.SystemSerialNumber = *spoofConfig.SystemSerialNumber
	}
	if spoofConfig.SystemProductName != nil {
		spoofed.SystemProductName = *spoofConfig.SystemProductName
	}
	if spoofConfig.SystemManufacturer != nil {
		spoofed.SystemManufacturer = *spoofConfig.SystemManufacturer
	}

	if spoofConfig.Environment != nil {
		if spoofConfig.Environment.Cloud != nil {
			spoofed.Environment.Cloud = *spoofConfig.Environment.Cloud
		}
		if spoofConfig.Environment.Platform != nil {
			spoofed.Environment.Platform = *spoofConfig.Environment.Platform
		}
	}

	if len(spoofConfig.NetworkAddresses) > 0 {
		spoofed.NetworkAddresses = make([]NetworkAddress, 0, len(spoofConfig.NetworkAddresses))
		for _, addr := range spoofConfig.NetworkAddresses {
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

	return &spoofed
}

// applySpoofing saves real values, applies overrides, and saves reported values.
// Returns the (possibly modified) Info to use.
func applySpoofing(info *Info) *Info {
	if !spoofEnabled() {
		return info
	}

	realSnap := infoToSnapshot(info)
	saveSnapshot(realSnap, filepath.Join(spoofDir, "real.json"))

	spoofed := applyOverrides(info)

	reportedSnap := infoToSnapshot(spoofed)
	saveSnapshot(reportedSnap, filepath.Join(spoofDir, "reported.json"))

	return spoofed
}
