package system

import (
	"context"
	"runtime"
	"strings"
	"syscall/js"

	"github.com/netbirdio/netbird/version"
)

// UpdateStaticInfoAsync is a no-op on JS as there is no static info to update
func UpdateStaticInfoAsync() {
	// do nothing
}

// GetInfo retrieves system information for WASM environment
func GetInfo(ctx context.Context) *Info {
	info := &Info{
		GoOS:           runtime.GOOS,
		Kernel:         runtime.GOARCH,
		KernelVersion:  runtime.GOARCH,
		Platform:       runtime.GOARCH,
		OS:             runtime.GOARCH,
		Hostname:       "wasm-client",
		CPUs:           runtime.NumCPU(),
		NetbirdVersion: version.NetbirdVersion(),
		DiskEncryption: detectDiskEncryption(ctx),
	}

	collectBrowserInfo(info)
	collectLocationInfo(info)
	collectSystemInfo(info)
	return info
}

func collectBrowserInfo(info *Info) {
	navigator := js.Global().Get("navigator")
	if navigator.IsUndefined() {
		return
	}

	collectUserAgent(info, navigator)
	collectPlatform(info, navigator)
	collectCPUInfo(info, navigator)
}

func collectUserAgent(info *Info, navigator js.Value) {
	ua := navigator.Get("userAgent")
	if ua.IsUndefined() {
		return
	}

	userAgent := ua.String()
	os, osVersion := parseOSFromUserAgent(userAgent)
	if os != "" {
		info.OS = os
	}
	if osVersion != "" {
		info.OSVersion = osVersion
	}
}

func collectPlatform(info *Info, navigator js.Value) {
	// Try regular platform property
	if plat := navigator.Get("platform"); !plat.IsUndefined() {
		if platStr := plat.String(); platStr != "" {
			info.Platform = platStr
		}
	}

	// Try newer userAgentData API for more accurate platform
	userAgentData := navigator.Get("userAgentData")
	if userAgentData.IsUndefined() {
		return
	}

	platformInfo := userAgentData.Get("platform")
	if !platformInfo.IsUndefined() {
		if platStr := platformInfo.String(); platStr != "" {
			info.Platform = platStr
		}
	}
}

func collectCPUInfo(info *Info, navigator js.Value) {
	hardwareConcurrency := navigator.Get("hardwareConcurrency")
	if !hardwareConcurrency.IsUndefined() {
		info.CPUs = hardwareConcurrency.Int()
	}
}

func collectLocationInfo(info *Info) {
	location := js.Global().Get("location")
	if location.IsUndefined() {
		return
	}

	if host := location.Get("hostname"); !host.IsUndefined() {
		hostnameStr := host.String()
		if hostnameStr != "" && hostnameStr != "localhost" {
			info.Hostname = hostnameStr
		}
	}
}

func checkFileAndProcess(_ []string) ([]File, error) {
	return []File{}, nil
}

func collectSystemInfo(info *Info) {
	navigator := js.Global().Get("navigator")
	if navigator.IsUndefined() {
		return
	}

	if vendor := navigator.Get("vendor"); !vendor.IsUndefined() {
		info.SystemManufacturer = vendor.String()
	}

	if product := navigator.Get("product"); !product.IsUndefined() {
		info.SystemProductName = product.String()
	}

	if userAgent := navigator.Get("userAgent"); !userAgent.IsUndefined() {
		ua := userAgent.String()
		info.Environment = detectEnvironmentFromUA(ua)
	}
}

func parseOSFromUserAgent(userAgent string) (string, string) {
	if userAgent == "" {
		return "", ""
	}

	switch {
	case strings.Contains(userAgent, "Windows NT"):
		return parseWindowsVersion(userAgent)
	case strings.Contains(userAgent, "Mac OS X"):
		return parseMacOSVersion(userAgent)
	case strings.Contains(userAgent, "FreeBSD"):
		return "FreeBSD", ""
	case strings.Contains(userAgent, "OpenBSD"):
		return "OpenBSD", ""
	case strings.Contains(userAgent, "NetBSD"):
		return "NetBSD", ""
	case strings.Contains(userAgent, "Linux"):
		return parseLinuxVersion(userAgent)
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad"):
		return parseiOSVersion(userAgent)
	case strings.Contains(userAgent, "CrOS"):
		return "ChromeOS", ""
	default:
		return "", ""
	}
}

func parseWindowsVersion(userAgent string) (string, string) {
	switch {
	case strings.Contains(userAgent, "Windows NT 10.0; Win64; x64"):
		return "Windows", "10/11"
	case strings.Contains(userAgent, "Windows NT 10.0"):
		return "Windows", "10"
	case strings.Contains(userAgent, "Windows NT 6.3"):
		return "Windows", "8.1"
	case strings.Contains(userAgent, "Windows NT 6.2"):
		return "Windows", "8"
	case strings.Contains(userAgent, "Windows NT 6.1"):
		return "Windows", "7"
	default:
		return "Windows", "Unknown"
	}
}

func parseMacOSVersion(userAgent string) (string, string) {
	idx := strings.Index(userAgent, "Mac OS X ")
	if idx == -1 {
		return "macOS", "Unknown"
	}

	versionStart := idx + len("Mac OS X ")
	versionEnd := strings.Index(userAgent[versionStart:], ")")
	if versionEnd <= 0 {
		return "macOS", "Unknown"
	}

	ver := userAgent[versionStart : versionStart+versionEnd]
	ver = strings.ReplaceAll(ver, "_", ".")
	return "macOS", ver
}

func parseLinuxVersion(userAgent string) (string, string) {
	if strings.Contains(userAgent, "Android") {
		return "Android", extractAndroidVersion(userAgent)
	}
	if strings.Contains(userAgent, "Ubuntu") {
		return "Ubuntu", ""
	}
	return "Linux", ""
}

func parseiOSVersion(userAgent string) (string, string) {
	idx := strings.Index(userAgent, "OS ")
	if idx == -1 {
		return "iOS", "Unknown"
	}

	versionStart := idx + 3
	versionEnd := strings.Index(userAgent[versionStart:], " ")
	if versionEnd <= 0 {
		return "iOS", "Unknown"
	}

	ver := userAgent[versionStart : versionStart+versionEnd]
	ver = strings.ReplaceAll(ver, "_", ".")
	return "iOS", ver
}

func extractAndroidVersion(userAgent string) string {
	if idx := strings.Index(userAgent, "Android "); idx != -1 {
		versionStart := idx + len("Android ")
		versionEnd := strings.IndexAny(userAgent[versionStart:], ";)")
		if versionEnd > 0 {
			return userAgent[versionStart : versionStart+versionEnd]
		}
	}
	return "Unknown"
}

func detectEnvironmentFromUA(_ string) Environment {
	return Environment{}
}
