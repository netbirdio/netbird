//go:build !js

package ssh

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"

	"github.com/netbirdio/netbird/util"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func getLoginCmd(user string, remoteAddr net.Addr) (loginPath string, args []string, err error) {
	if !isRoot() {
		shell := getUserShell(user)
		if shell == "" {
			shell = "/bin/sh"
		}

		return shell, []string{"-l"}, nil
	}

	loginPath, err = exec.LookPath("login")
	if err != nil {
		return "", nil, err
	}

	addrPort, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil {
		return "", nil, err
	}

	switch runtime.GOOS {
	case "linux":
		if util.FileExists("/etc/arch-release") && !util.FileExists("/etc/pam.d/remote") {
			return loginPath, []string{"-f", user, "-p"}, nil
		}
		return loginPath, []string{"-f", user, "-h", addrPort.Addr().String(), "-p"}, nil
	case "darwin":
		return loginPath, []string{"-fp", "-h", addrPort.Addr().String(), user}, nil
	case "freebsd":
		return loginPath, []string{"-f", user, "-h", addrPort.Addr().String(), "-p"}, nil
	default:
		return "", nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
