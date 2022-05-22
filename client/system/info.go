package system

// this is the wiretrustee version
// will be replaced with the release version when using goreleaser
var version = "development"

//Info is an object that contains machine information
// Most of the code is taken from https://github.com/matishsiao/goInfo
type Info struct {
	GoOS               string
	Kernel             string
	Core               string
	Platform           string
	OS                 string
	OSVersion          string
	Hostname           string
	CPUs               int
	WiretrusteeVersion string
	Caller             string
	CallerVersion      string
}

func WiretrusteeVersion() string {
	return version
}

func NetBirdDesktopUIUserAgent() string {
	return "netbird-desktop-ui/" + WiretrusteeVersion()
}

func NetBirdCmdUserAgent() string {
	return "netbird-cli/" + WiretrusteeVersion()
}
