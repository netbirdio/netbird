package updater

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updater/installer"
)

func isAutoUpdateSupported() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	isBrew := !installer.TypeOfInstaller(ctx).Downloadable()
	if isBrew {
		log.Warnf("auto-update disabled on Homebrew installation")
		return false
	}
	return true
}
