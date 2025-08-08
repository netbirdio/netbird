//go:build windows

package updatemanager

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os/exec"

	"golang.org/x/sys/windows/registry"
)

const (
	msiDownloadURL     = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.msi"
	exeDownloadURL     = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.exe"
	uninstallKeyPath64 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
	uninstallKeyPath32 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
)

func installationMethod() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath64, registry.QUERY_VALUE)
	if err != nil {
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath32, registry.QUERY_VALUE)
		if err != nil {
			return "MSI"
		} else {
			err = k.Close()
			if err != nil {
				log.Warnf("Error closing registry key: %v", err)
			}
		}
	} else {
		err = k.Close()
		if err != nil {
			log.Warnf("Error closing registry key: %v", err)
		}
	}
	return "EXE"
}

func (u *UpdateManager) updateMSI(targetVersion string) error {
	path, err := downloadFileToTemporaryDir(u.ctx, urlWithVersionArch(msiDownloadURL, targetVersion))
	if err != nil {
		return err
	}
	cmd := exec.Command("msiexec", "/quiet", "/i", path)
	err = cmd.Run()
	return err
}

func (u *UpdateManager) updateEXE(targetVersion string) error {
	path, err := downloadFileToTemporaryDir(u.ctx, urlWithVersionArch(exeDownloadURL, targetVersion))
	if err != nil {
		return err
	}
	cmd := exec.Command(path, "/S")
	err = cmd.Start()
	if err != nil {
		return err
	}
	err = cmd.Process.Release()

	return err
}

func (u *UpdateManager) triggerUpdate(targetVersion string) error {
	switch installationMethod() {
	case "EXE":
		return u.updateEXE(targetVersion)
	case "MSI":
		return u.updateMSI(targetVersion)
	default:
		return fmt.Errorf("unsupported installation method: %s", installationMethod())
	}
}
