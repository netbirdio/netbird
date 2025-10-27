//go:build windows

package updatemanager

import (
	"context"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
)

const (
	msiDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.msi"
	exeDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_installer_%version_windows_%arch.exe"
)

func (m *Manager) triggerUpdate(ctx context.Context, targetVersion string) error {
	it := installer.TypeByRegistry()
	inst := installer.NewInstaller()
	tmpDir, err := inst.CreateTempDir()
	if err != nil {
		return err
	}

	installerPath, err := downloadFileToTemporaryDir(ctx, tmpDir, urlWithVersionArch(it, targetVersion))
	if err != nil {
		return err
	}
	log.Debugf("installer path: %s", installerPath)

	if err := inst.RunInstallation(installerPath); err != nil {
		return err
	}
	return nil
}

func urlWithVersionArch(it installer.InstallerType, version string) string {
	var url string
	if it == installer.TypeExe {
		url = exeDownloadURL
	} else {
		url = msiDownloadURL
	}
	url = strings.ReplaceAll(url, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
