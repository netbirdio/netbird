package updater

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updater/installer"
)

func isAutoUpdateSupported() bool {
	isBrew := !installer.TypeOfInstaller(context.Background()).Downloadable()
	if isBrew {
		log.Warnf("auto-update disabled on Homebrew installation")
		return false
	}
	return true
}
