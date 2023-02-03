package system

import (
	"bytes"
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	version, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		log.Warnf("got an error while retrieving macOS version with sw_vers, error: %s. Using darwin version instead.\n", err)
		version = []byte(release)
	}
	gio := &Info{Kernel: sysName, OSVersion: strings.TrimSpace(string(version)), Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
