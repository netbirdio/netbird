package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	utsname := unix.Utsname{}
	err := unix.Uname(&utsname)
	if err != nil {
		fmt.Println("getInfo:", err)
	}
	sysName := string(bytes.Split(utsname.Sysname[:], []byte{0})[0])
	machine := string(bytes.Split(utsname.Machine[:], []byte{0})[0])
	release := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	swVersion, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		log.Warnf("got an error while retrieving macOS version with sw_vers, error: %s. Using darwin version instead.\n", err)
		swVersion = []byte(release)
	}
	gio := &Info{Kernel: sysName, OSVersion: strings.TrimSpace(string(swVersion)), Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
