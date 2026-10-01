package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// TriggerUpdate initiates installation of the pending enforced version.
// It is called when the user clicks the install button in the UI (Mode 2 / enforced update).
func (s *Server) TriggerUpdate(ctx context.Context, _ *proto.TriggerUpdateRequest) (*proto.TriggerUpdateResponse, error) {
	if s.updateManager == nil {
		return &proto.TriggerUpdateResponse{Success: false, ErrorMsg: "update manager not available"}, nil
	}

	if err := s.updateManager.Install(ctx); err != nil {
		log.Warnf("TriggerUpdate failed: %v", err)
		return &proto.TriggerUpdateResponse{Success: false, ErrorMsg: err.Error()}, nil
	}

	return &proto.TriggerUpdateResponse{Success: true}, nil
}
