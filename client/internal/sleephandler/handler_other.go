//go:build !darwin || ios || !cgo

package sleephandler

import (
	"context"

	log "github.com/sirupsen/logrus"
)

type SleepHandler struct {
	callbacks SleepCallbacks
}

type SleepCallbacks struct {
	OnSleep func(context.Context) error
	OnWake  func(context.Context) error
}

func New(ctx context.Context, callbacks SleepCallbacks) *SleepHandler {
	return &SleepHandler{
		callbacks: callbacks,
	}
}

func (sh *SleepHandler) Start(ctx context.Context) error {
	log.Debugf("sleep handler not available on this platform")
	return nil
}

func (sh *SleepHandler) Stop() {
	log.Debugf("sleep handler not available on this platform")
}
