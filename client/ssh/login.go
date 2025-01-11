package ssh

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"

	"github.com/netbirdio/netbird/util"
)

func getLoginCmd(user string, remoteAddr net.Addr) (loginPath string, args []string, err error) {
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
