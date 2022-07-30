package system

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
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
	gio := &Info{Kernel: sysName, OSVersion: release, Core: release, Platform: machine, OS: sysName, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}
