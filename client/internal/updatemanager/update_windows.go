//go:build windows

package updatemanager

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"os/exec"

	log "github.com/sirupsen/logrus"
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

func updateMSI(ctx context.Context, targetVersion string) error {
	path, err := downloadFileToTemporaryDir(ctx, urlWithVersionArch(msiDownloadURL, targetVersion))
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "msiexec", "/quiet", "/i", path)
	err = cmd.Run()
	return err
}

func updateEXE(ctx context.Context, targetVersion string) error {
	path, err := downloadFileToTemporaryDir(ctx, urlWithVersionArch(exeDownloadURL, targetVersion))
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, "/S")
	err = cmd.Start()
	if err != nil {
		return err
	}
	err = cmd.Process.Release()

	return err
}

func triggerUpdate(ctx context.Context, targetVersion string) error {
	switch installationMethod() {
	case "EXE":
		return updateEXE(ctx, targetVersion)
	case "MSI":
		return updateMSI(ctx, targetVersion)
	default:
		return fmt.Errorf("unsupported installation method: %s", installationMethod())
	}
}
