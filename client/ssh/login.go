package ssh

import (
	"fmt"
	"github.com/netbirdio/netbird/util"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
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

	if runtime.GOOS == "linux" {

		if util.FileExists("/etc/arch-release") && !util.FileExists("/etc/pam.d/remote") {
			// detect if Arch Linux
			return loginPath, []string{"-f", user, "-p"}, nil
		}

		return loginPath, []string{"-f", user, "-h", addrPort.Addr().String(), "-p"}, nil
	} else if runtime.GOOS == "darwin" {
		return loginPath, []string{"-fp", "-h", addrPort.Addr().String(), user}, nil
	}

	return "", nil, fmt.Errorf("unsupported platform")
}
