package installer

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	uninstallKeyPath64 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
	uninstallKeyPath32 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Netbird`
)

var (
	TypeExe = Type{name: "EXE", downloadable: true}
	TypeMSI = Type{name: "MSI", downloadable: true}
)

func TypeOfInstaller(_ context.Context) Type {
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

func typeByFileExtension(filePath string) (Type, error) {
	switch {
	case strings.HasSuffix(strings.ToLower(filePath), ".exe"):
		return TypeExe, nil
	case strings.HasSuffix(strings.ToLower(filePath), ".msi"):
		return TypeMSI, nil
	default:
		return Type{}, fmt.Errorf("unsupported installer type for file: %s", filePath)
	}
}
