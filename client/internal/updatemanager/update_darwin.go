//go:build darwin

package updatemanager

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
)

const (
	pkgDownloadURL = "https://github.com/netbirdio/netbird/releases/download/v%version/netbird_%version_darwin_%arch.pkg"
)

func (m *Manager) triggerUpdate(ctx context.Context, targetVersion string) error {
	inst, err := installer.New()
	if err != nil {
		return err
	}

	var installerFile string
	if installer.TypeOfInstaller(ctx) == installer.TypePKG {
		tmpDir, err := inst.MakeTempDir()
		if err != nil {
			return err
		}

		installerFile, err = downloadFileToTemporaryDir(ctx, tmpDir, urlWithVersionArch(targetVersion))
		if err != nil {
			return fmt.Errorf("error downloading update file: %w", err)
		}
	}

	if err := inst.RunInstallation(installerFile); err != nil {
		return err
	}

	return err
}

func urlWithVersionArch(version string) string {
	url := strings.ReplaceAll(pkgDownloadURL, "%version", version)
	return strings.ReplaceAll(url, "%arch", runtime.GOARCH)
}
