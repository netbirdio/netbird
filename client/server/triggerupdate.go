package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// TriggerUpdate initiates installation of the pending enforced version.
// It is called when the user clicks the install button in the UI (Mode 2 / enforced update).
func (s *Server) TriggerUpdate(ctx context.Context, _ *proto.TriggerUpdateRequest) (*proto.TriggerUpdateResponse, error) {
	s.mutex.Lock()
	cc := s.connectClient
	s.mutex.Unlock()

	if cc == nil {
		return &proto.TriggerUpdateResponse{Success: false, ErrorMsg: "service is not connected"}, nil
	}

	engine := cc.Engine()
	if engine == nil {
		return &proto.TriggerUpdateResponse{Success: false, ErrorMsg: "engine is not initialized"}, nil
	}

	if err := engine.TriggerUpdate(ctx); err != nil {
		log.Warnf("TriggerUpdate failed: %v", err)
		return &proto.TriggerUpdateResponse{Success: false, ErrorMsg: err.Error()}, nil
	}

	return &proto.TriggerUpdateResponse{Success: true}, nil
}
