package system

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestGetInfo(t *testing.T) {
	info := GetInfo(context.Background())
	log.Infof("info: %+v", info)
}
