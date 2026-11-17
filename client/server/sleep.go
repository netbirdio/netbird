package server

import (
	"context"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/sleep"
	"github.com/netbirdio/netbird/client/proto"
)

const envDisableSleepDetector = "NB_DISABLE_SLEEP_DETECTOR"

// serverAgent adapts Server to the handler.Agent and handler.StatusChecker interfaces
type serverAgent struct {
	s *Server
}

func (a *serverAgent) Up(ctx context.Context) error {
	_, err := a.s.Up(ctx, &proto.UpRequest{})
	return err
}

func (a *serverAgent) Down(ctx context.Context) error {
	_, err := a.s.Down(ctx, &proto.DownRequest{})
	return err
}

func (a *serverAgent) Status() (internal.StatusType, error) {
	return internal.CtxGetState(a.s.rootCtx).Status()
}

// startSleepDetector starts the OS sleep/wake detector and forwards events to
// the sleep handler. On platforms without a supported detector the attempt
// logs a warning and returns. Setting NB_DISABLE_SLEEP_DETECTOR=true skips
// registration entirely.
func (s *Server) startSleepDetector() {
	if sleepDetectorDisabled() {
		log.Info("sleep detection disabled via " + envDisableSleepDetector)
		return
	}

	svc, err := sleep.New()
	if err != nil {
		log.Warnf("failed to initialize sleep detection: %v", err)
		return
	}

	err = svc.Register(func(event sleep.EventType) {
		switch event {
		case sleep.EventTypeSleep:
			log.Info("handling sleep event")
			if err := s.sleepHandler.HandleSleep(s.rootCtx); err != nil {
				log.Errorf("failed to handle sleep event: %v", err)
			}
		case sleep.EventTypeWakeUp:
			log.Info("handling wakeup event")
			if err := s.sleepHandler.HandleWakeUp(s.rootCtx); err != nil {
				log.Errorf("failed to handle wakeup event: %v", err)
			}
		}
	})
	if err != nil {
		log.Errorf("failed to register sleep detector: %v", err)
		return
	}

	log.Info("sleep detection service initialized")

	go func() {
		<-s.rootCtx.Done()
		log.Info("stopping sleep event listener")
		if err := svc.Deregister(); err != nil {
			log.Errorf("failed to deregister sleep detector: %v", err)
		}
	}()
}

func sleepDetectorDisabled() bool {
	val := os.Getenv(envDisableSleepDetector)
	if val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s=%q: %v", envDisableSleepDetector, val, err)
		return false
	}
	return disabled
}
