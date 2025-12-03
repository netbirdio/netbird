package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// NotifyOSLifecycle handles operating system lifecycle events by executing appropriate logic based on the request type.
func (s *Server) NotifyOSLifecycle(callerCtx context.Context, req *proto.OSLifecycleRequest) (*proto.OSLifecycleResponse, error) {
	switch req.GetType() {
	case proto.OSLifecycleRequest_WAKEUP:
		return s.handleWakeUp(callerCtx)
	case proto.OSLifecycleRequest_SLEEP:
		return s.handleSleep(callerCtx)
	default:
		log.Errorf("unknown OSLifecycleRequest type: %v", req.GetType())
	}
	return &proto.OSLifecycleResponse{}, nil
}

// handleWakeUp processes a wake-up event by triggering the Up command if the system was previously put to sleep.
// It resets the sleep state and logs the process. Returns a response or an error if the Up command fails.
func (s *Server) handleWakeUp(callerCtx context.Context) (*proto.OSLifecycleResponse, error) {
	if !s.sleepTriggeredDown.Load() {
		log.Info("skipping up because wasn't sleep down")
		return &proto.OSLifecycleResponse{}, nil
	}

	// avoid other wakeup runs if sleep didn't make the computer sleep
	s.sleepTriggeredDown.Store(false)

	log.Info("running up after wake up")
	_, err := s.Up(callerCtx, &proto.UpRequest{})
	if err != nil {
		log.Errorf("running up failed: %v", err)
		return &proto.OSLifecycleResponse{}, err
	}

	log.Info("running up command executed successfully")
	return &proto.OSLifecycleResponse{}, nil
}

// handleSleep handles the sleep event by initiating a "down" sequence if the system is in a connected or connecting state.
func (s *Server) handleSleep(callerCtx context.Context) (*proto.OSLifecycleResponse, error) {
	s.mutex.Lock()

	state := internal.CtxGetState(s.rootCtx)
	status, err := state.Status()
	if err != nil {
		s.mutex.Unlock()
		return &proto.OSLifecycleResponse{}, err
	}

	if status != internal.StatusConnecting && status != internal.StatusConnected {
		log.Infof("skipping setting the agent down because status is %s", status)
		s.mutex.Unlock()
		return &proto.OSLifecycleResponse{}, nil
	}
	s.mutex.Unlock()

	log.Info("running down after system started sleeping")

	_, err = s.Down(callerCtx, &proto.DownRequest{})
	if err != nil {
		log.Errorf("running down failed: %v", err)
		return &proto.OSLifecycleResponse{}, err
	}

	s.sleepTriggeredDown.Store(true)

	log.Info("running down executed successfully")
	return &proto.OSLifecycleResponse{}, nil
}
