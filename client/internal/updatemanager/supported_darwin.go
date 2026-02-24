package updatemanager

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
)

func isAutoUpdateSupported() bool {
	isBrew := !installer.TypeOfInstaller(context.Background()).Downloadable()
	if isBrew {
		log.Warnf("auto-update disabled on Home Brew installation")
		return false
	}
	return true
}
