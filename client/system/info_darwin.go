package system

import (
	"bytes"
	"context"
	"fmt"
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
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	// If there is an error while getting version, returning darwin version instead
	var gio *Info
	if err == nil {
		version := strings.TrimSpace(string(out))
		gio = &Info{Kernel: sysName, OSVersion: version, Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	} else {
		gio = &Info{Kernel: sysName, OSVersion: release, Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
