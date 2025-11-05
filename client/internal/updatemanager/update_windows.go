//go:build windows

package updatemanager

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	msiDownloadURL     = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.msi"
	exeDownloadURL     = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.exe"
	uninstallKeyPath64 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
	uninstallKeyPath32 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`

	installerEXE installerType = "EXE"
	installerMSI installerType = "MSI"
)

type installerType string

func (u *UpdateManager) triggerUpdate(ctx context.Context, targetVersion string) error {
	// Use test function if set (for testing purposes)
	if u.updateFunc != nil {
		return u.updateFunc(ctx, targetVersion)
	}

	method := installation()
	return install(ctx, method, targetVersion)
}

func installation() installerType {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath64, registry.QUERY_VALUE)
	if err != nil {
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, uninstallKeyPath32, registry.QUERY_VALUE)
		if err != nil {
			return installerMSI
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
	return installerEXE
}

func install(ctx context.Context, installerType installerType, targetVersion string) error {
	path, err := downloadFileToTemporaryDir(ctx, urlWithVersionArch(installerType, targetVersion))
	if err != nil {
		return err
	}
	log.Infof("start installation %s", path)

	var cmd *exec.Cmd
	if installerType == installerEXE {
		cmd = exec.CommandContext(ctx, path, "/S")
	} else {
		cmd = exec.CommandContext(ctx, "msiexec", "/quiet", "/i", path)
	}

	// Detach the process from the parent
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // 0x00000008 is DETACHED_PROCESS
	}

	if err := cmd.Start(); err != nil {
		log.Errorf("error starting installer: %v", err)
		return err
	}

	if err := cmd.Process.Release(); err != nil {
		log.Errorf("error releasing installer process: %v", err)
		return err
	}

	log.Infof("installer started successfully: %s", path)
	return nil
}

func urlWithVersionArch(it installerType, version string) string {
	var url string
	if it == installerEXE {
		url = exeDownloadURL
	} else {
		url = msiDownloadURL
	}
	url = strings.ReplaceAll(url, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
