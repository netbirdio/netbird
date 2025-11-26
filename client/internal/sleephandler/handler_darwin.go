//go:build darwin && !ios && cgo

package sleephandler

import (
	"context"
	"sync"

	"github.com/prashantgupta24/mac-sleep-notifier/notifier"
	log "github.com/sirupsen/logrus"
)

type SleepHandler struct {
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	callbacks        SleepCallbacks
	rootCtx          context.Context
	notifierInstance *notifier.Notifier
}

type SleepCallbacks struct {
	OnSleep func(context.Context) error
	OnWake  func(context.Context) error
}

func New(ctx context.Context, callbacks SleepCallbacks) *SleepHandler {
	return &SleepHandler{
		callbacks: callbacks,
		rootCtx:   ctx,
	}
}

func (sh *SleepHandler) Start(ctx context.Context) error {
	sh.ctx, sh.cancel = context.WithCancel(ctx)

	sh.wg.Add(1)
	go sh.listenForSleepWake()

	log.Infof("sleep handler started")
	return nil
}

func (sh *SleepHandler) Stop() {
	if sh.cancel != nil {
		sh.cancel()
	}
	sh.wg.Wait()
	if sh.notifierInstance != nil {
		sh.notifierInstance.Quit()
	}
	log.Infof("sleep handler stopped")
}

func (sh *SleepHandler) listenForSleepWake() {
	defer sh.wg.Done()

	sh.notifierInstance = notifier.GetInstance()
	if sh.notifierInstance == nil {
		log.Errorf("failed to get notifier instance")
		return
	}

	activityChan := sh.notifierInstance.Start()

	for {
		select {
		case <-sh.ctx.Done():
			log.Debugf("sleep handler context canceled")
			return

		case activity := <-activityChan:
			if activity == nil {
				log.Debugf("activity channel closed")
				return
			}

			switch activity.Type {
			case notifier.Sleep:
				log.Infof("sleep event detected, calling OnSleep callback")
				if sh.callbacks.OnSleep != nil {
					if err := sh.callbacks.OnSleep(sh.rootCtx); err != nil {
						log.Errorf("OnSleep callback failed: %v", err)
					}
				}

			case notifier.Awake:
				log.Infof("wake event detected, calling OnWake callback")
				if sh.callbacks.OnWake != nil {
					if err := sh.callbacks.OnWake(sh.rootCtx); err != nil {
						log.Errorf("OnWake callback failed: %v", err)
					}
				}
			}
		}
	}
}
