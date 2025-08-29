package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// ListStates returns a list of all saved states
func (s *Server) ListStates(_ context.Context, _ *proto.ListStatesRequest) (*proto.ListStatesResponse, error) {
	mgr := statemanager.New(s.profileManager.GetStatePath())

	stateNames, err := mgr.GetSavedStateNames()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get saved state names: %v", err)
	}

	states := make([]*proto.State, 0, len(stateNames))
	for _, name := range stateNames {
		states = append(states, &proto.State{
			Name: name,
		})
	}

	return &proto.ListStatesResponse{
		States: states,
	}, nil
}

// CleanState handles cleaning of states (performing cleanup operations)
func (s *Server) CleanState(ctx context.Context, req *proto.CleanStateRequest) (*proto.CleanStateResponse, error) {
	if s.connectClient.Status() == internal.StatusConnected || s.connectClient.Status() == internal.StatusConnecting {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot clean state while connecting or connected, run 'netbird down' first.")
	}

	statePath := s.profileManager.GetStatePath()

	if req.All {
		// Reuse existing cleanup logic for all states
		if err := restoreResidualState(ctx, statePath); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to clean all states: %v", err)
		}

		// Get count of cleaned states
		mgr := statemanager.New(statePath)
		stateNames, err := mgr.GetSavedStateNames()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get state count: %v", err)
		}

		return &proto.CleanStateResponse{
			CleanedStates: int32(len(stateNames)),
		}, nil
	}

	// Handle single state cleanup
	mgr := statemanager.New(statePath)
	registerStates(mgr)

	if err := mgr.CleanupStateByName(req.StateName); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to clean state %s: %v", req.StateName, err)
	}

	if err := mgr.PersistState(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to persist state changes: %v", err)
	}

	return &proto.CleanStateResponse{
		CleanedStates: 1,
	}, nil
}

// DeleteState handles deletion of states without cleanup
func (s *Server) DeleteState(ctx context.Context, req *proto.DeleteStateRequest) (*proto.DeleteStateResponse, error) {
	if s.connectClient.Status() == internal.StatusConnected || s.connectClient.Status() == internal.StatusConnecting {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot clean state while connecting or connected, run 'netbird down' first.")
	}

	mgr := statemanager.New(s.profileManager.GetStatePath())

	var count int
	var err error

	if req.All {
		count, err = mgr.DeleteAllStates()
	} else {
		err = mgr.DeleteStateByName(req.StateName)
		if err == nil {
			count = 1
		}
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete state: %v", err)
	}

	// Persist the changes
	if err := mgr.PersistState(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to persist state changes: %v", err)
	}

	return &proto.DeleteStateResponse{
		DeletedStates: int32(count),
	}, nil
}

// restoreResidualState checks if the client was not shut down in a clean way and restores residual if required.
// Otherwise, we might not be able to connect to the management server to retrieve new config.
func restoreResidualState(ctx context.Context, statePath string) error {
	if statePath == "" {
		return nil
	}

	mgr := statemanager.New(statePath)

	// register the states we are interested in restoring
	registerStates(mgr)

	var merr *multierror.Error

	if err := mgr.PerformCleanup(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("perform cleanup: %w", err))
	}

	// persist state regardless of cleanup outcome. It could've succeeded partially
	if err := mgr.PersistState(ctx); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("persist state: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}
