package handler

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
)

type Agent interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Status() (internal.StatusType, error)
}

type SleepHandler struct {
	agent Agent

	mu sync.Mutex
	// sleepTriggeredDown indicates whether the sleep handler triggered the last client down, to avoid unnecessary up on wake
	sleepTriggeredDown bool
}

func New(agent Agent) *SleepHandler {
	return &SleepHandler{
		agent: agent,
	}
}

func (s *SleepHandler) HandleWakeUp(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.sleepTriggeredDown {
		log.Info("skipping up because wasn't sleep down")
		return nil
	}

	// avoid other wakeup runs if sleep didn't make the computer sleep
	s.sleepTriggeredDown = false

	log.Info("running up after wake up")
	err := s.agent.Up(ctx)
	if err != nil {
		log.Errorf("running up failed: %v", err)
		return err
	}

	log.Info("running up command executed successfully")
	return nil
}

func (s *SleepHandler) HandleSleep(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, err := s.agent.Status()
	if err != nil {
		return err
	}

	if status != internal.StatusConnecting && status != internal.StatusConnected {
		log.Infof("skipping setting the agent down because status is %s", status)
		return nil
	}

	log.Info("running down after system started sleeping")

	if err = s.agent.Down(ctx); err != nil {
		log.Errorf("running down failed: %v", err)
		return err
	}

	s.sleepTriggeredDown = true

	log.Info("running down executed successfully")
	return nil
}
