package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

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

// NotifyOSLifecycle handles operating system lifecycle events by executing appropriate logic based on the request type.
func (s *Server) NotifyOSLifecycle(callerCtx context.Context, req *proto.OSLifecycleRequest) (*proto.OSLifecycleResponse, error) {
	switch req.GetType() {
	case proto.OSLifecycleRequest_WAKEUP:
		if err := s.sleepHandler.HandleWakeUp(callerCtx); err != nil {
			return &proto.OSLifecycleResponse{}, err
		}
	case proto.OSLifecycleRequest_SLEEP:
		if err := s.sleepHandler.HandleSleep(callerCtx); err != nil {
			return &proto.OSLifecycleResponse{}, err
		}
	default:
		log.Errorf("unknown OSLifecycleRequest type: %v", req.GetType())
	}
	return &proto.OSLifecycleResponse{}, nil
}
