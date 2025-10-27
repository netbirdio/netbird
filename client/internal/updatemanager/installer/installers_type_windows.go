package installer

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	uninstallKeyPath64 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
	uninstallKeyPath32 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`

	TypeExe InstallerType = "EXE"
	TypeMSI InstallerType = "MSI"
)

type InstallerType string

func TypeByRegistry() InstallerType {
	paths := []string{uninstallKeyPath64, uninstallKeyPath32}

	for _, path := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		if err := k.Close(); err != nil {
			log.Warnf("Error closing registry key: %v", err)
		}
		return TypeExe

	}

	log.Debug("No registry entry found for Netbird, assuming MSI installation")
	return TypeMSI
}

func TypeByFileExtension(filePath string) (InstallerType, error) {
	switch {
	case strings.HasSuffix(strings.ToLower(filePath), ".exe"):
		return TypeExe, nil
	case strings.HasSuffix(strings.ToLower(filePath), ".msi"):
		return TypeMSI, nil
	default:
		return "", fmt.Errorf("unsupported installer type for file: %s", filePath)
	}
}
