package server

import (
	"context"
	"fmt"
	"slices"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/owner"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

// authorizeTargetProfile enforces the "match or root" rule for operations
// that target a specific profile (Remove/Switch). The caller must be root
// or appear in the target profile config's OwnerUIDs. A target profile in
// legacy TOFU state (nil OwnerUIDs) is treated as unowned and therefore
// accessible to any peer-creds caller, which matches pre-enforcement
// behavior on upgraded installs.
func (s *Server) authorizeTargetProfile(ctx context.Context, profileName, username string) error {
	uid, ok := owner.UIDFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "peer credentials unavailable")
	}
	if uid == 0 {
		return nil
	}

	cfg, err := s.readProfileConfig(profileName, username)
	if err != nil {
		return fmt.Errorf("read target profile config: %w", err)
	}

	// Legacy / never-claimed target: allow, mirroring the migration TOFU
	// semantics in the interceptor.
	if cfg.OwnerUIDs == nil {
		return nil
	}

	if slices.Contains(cfg.OwnerUIDs, uid) {
		return nil
	}

	return status.Errorf(codes.PermissionDenied,
		"profile %q is owned by another user (uid %d is not in its owner list)", profileName, uid)
}

// readProfileConfig loads a profile's config from disk without making it
// active. Used by authorizeTargetProfile.
func (s *Server) readProfileConfig(profileName, username string) (*profilemanager.Config, error) {
	state := &profilemanager.ActiveProfileState{Name: profileName, Username: username}
	path, err := state.FilePath()
	if err != nil {
		return nil, fmt.Errorf("resolve profile path: %w", err)
	}
	cfg, err := profilemanager.GetConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	return cfg, nil
}

// GetOwnerUIDs returns the current owner UIDs from the active config.
// nil means TOFU mode, empty means root-only, populated means those UIDs are owners.
func (s *Server) GetOwnerUIDs() []owner.UID {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.config == nil {
		return nil
	}

	return s.config.OwnerUIDs
}

// AddOwnerUID adds the given UID to the owner list in the active profile config.
func (s *Server) AddOwnerUID(uid owner.UID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.addOwnerUIDLocked(uid)
}

// addOwnerUIDLocked adds uid to the active profile's owner list and persists it.
// The caller must hold s.mutex.
func (s *Server) addOwnerUIDLocked(uid owner.UID) error {
	if s.config == nil {
		return fmt.Errorf("config not loaded")
	}

	if slices.Contains(s.config.OwnerUIDs, uid) {
		return nil
	}

	s.config.OwnerUIDs = append(s.config.OwnerUIDs, uid)

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return fmt.Errorf("get active profile: %w", err)
	}

	cfgPath, err := activeProf.FilePath()
	if err != nil {
		return fmt.Errorf("get profile file path: %w", err)
	}

	if err := util.WriteJson(context.Background(), cfgPath, s.config); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	log.Infof("owner UID %d added in %s (owners: %v)", uid, cfgPath, s.config.OwnerUIDs)
	return nil
}

// AddOwner handles the AddOwner RPC. The interceptor has already gated this
// call (caller must be root or an existing owner); the handler just persists
// the new UID into the active profile config.
func (s *Server) AddOwner(_ context.Context, msg *proto.AddOwnerRequest) (*proto.AddOwnerResponse, error) {
	if msg == nil || msg.Uid == 0 {
		return nil, status.Error(codes.InvalidArgument, "uid must be non-zero")
	}
	if err := s.AddOwnerUID(owner.UID(msg.Uid)); err != nil {
		return nil, fmt.Errorf("add owner: %w", err)
	}
	return &proto.AddOwnerResponse{}, nil
}

// ResetOwner clears the active profile's owner list. Only callable by root
// (the interceptor enforces this: a non-owner non-root caller is denied
// before reaching the handler, and only owners or root can reach Add/Reset
// at all; we additionally require root here so existing owners can't reset
// each other out).
func (s *Server) ResetOwner(ctx context.Context, _ *proto.ResetOwnerRequest) (*proto.ResetOwnerResponse, error) {
	uid, ok := owner.UIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "peer credentials unavailable")
	}
	if uid != 0 {
		return nil, status.Error(codes.PermissionDenied, "reset-owner requires root")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.config == nil {
		return nil, fmt.Errorf("config not loaded")
	}

	// Reset to the fresh-install state (empty, not nil): only root and the
	// active console-session user can reclaim. nil would be legacy migration
	// TOFU, where any non-root caller (including SSH) could reclaim.
	s.config.OwnerUIDs = []owner.UID{}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	cfgPath, err := activeProf.FilePath()
	if err != nil {
		return nil, fmt.Errorf("get profile file path: %w", err)
	}
	if err := util.WriteJson(context.Background(), cfgPath, s.config); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	log.Infof("owner list reset; next call from the active console user will re-claim ownership")
	return &proto.ResetOwnerResponse{}, nil
}
