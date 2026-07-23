package server

import (
	"context"
	"fmt"
	"slices"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

// The daemon Server implements ipcauth.ProfilePolicy so the gRPC interceptor can
// authorize each RPC against the active profile's ownership.
var _ ipcauth.ProfilePolicy = (*Server)(nil)

// ActiveProfileOwnership returns the active profile's ownership policy. Reads
// the in-memory active config (kept current by the handlers), falling back to
// the on-disk active profile when the daemon hasn't loaded one yet.
func (s *Server) ActiveProfileOwnership() ipcauth.Ownership {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cfg := s.config
	if cfg == nil {
		loaded, err := s.loadActiveProfileConfigLocked()
		if err != nil {
			log.Warnf("ownership: cannot load active profile config, treating as unowned: %v", err)
			return ipcauth.Ownership{}
		}
		cfg = loaded
	}
	return ipcauth.Ownership{Owners: cfg.Owners, Shared: cfg.Shared}
}

// ClaimActiveProfileOwnerIfUnowned atomically claims the active profile for id
// when it has no owners and is not shared (trust-on-first-use). Returns whether
// id is now an owner. Concurrent first-callers are serialized by s.mutex, so
// exactly one wins the claim; the others get false and are authorized normally.
func (s *Server) ClaimActiveProfileOwnerIfUnowned(id ipcauth.Identity) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cfg := s.config
	if cfg == nil {
		loaded, err := s.loadActiveProfileConfigLocked()
		if err != nil {
			return false, fmt.Errorf("load active profile config: %w", err)
		}
		cfg = loaded
	}

	if len(cfg.Owners) > 0 || cfg.Shared {
		return false, nil // already owned or shared — someone won the race
	}

	cfg.Owners = []string{ipcauth.OwnerPrincipalForIdentity(id)}
	if err := s.persistActiveProfileConfigLocked(cfg); err != nil {
		cfg.Owners = nil // revert in-memory on persistence failure
		return false, fmt.Errorf("persist claimed ownership: %w", err)
	}
	s.config = cfg
	log.Infof("profile ownership claimed by %s (trust-on-first-use)", id)
	return true, nil
}

// activeProfileConfigPathLocked resolves the active profile's config file path.
func (s *Server) activeProfileConfigPathLocked() (string, error) {
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return "", fmt.Errorf("get active profile: %w", err)
	}
	path, err := activeProf.FilePath()
	if err != nil {
		return "", fmt.Errorf("resolve active profile path: %w", err)
	}
	return path, nil
}

// loadActiveProfileConfigLocked reads the active profile's config from disk.
func (s *Server) loadActiveProfileConfigLocked() (*profilemanager.Config, error) {
	path, err := s.activeProfileConfigPathLocked()
	if err != nil {
		return nil, err
	}
	return profilemanager.GetConfig(path)
}

// persistActiveProfileConfigLocked writes cfg to the active profile's config file.
func (s *Server) persistActiveProfileConfigLocked(cfg *profilemanager.Config) error {
	path, err := s.activeProfileConfigPathLocked()
	if err != nil {
		return err
	}
	return util.WriteJson(context.Background(), path, cfg)
}

// activeConfigLocked returns the in-memory active config, loading it from disk
// if the daemon hasn't cached one. Caller must hold s.mutex.
func (s *Server) activeConfigLocked() (*profilemanager.Config, error) {
	if s.config != nil {
		return s.config, nil
	}
	return s.loadActiveProfileConfigLocked()
}

// claimForCallerLocked adds the caller's principal to cfg (if absent) and
// persists. No-op for privileged callers (they need no ownership entry). Caller
// must hold s.mutex.
func (s *Server) claimForCallerLocked(id ipcauth.Identity, cfg *profilemanager.Config) error {
	if id.IsPrivileged() {
		return nil
	}
	principal := ipcauth.OwnerPrincipalForIdentity(id)
	if slices.Contains(cfg.Owners, principal) {
		return nil
	}
	cfg.Owners = append(cfg.Owners, principal)
	if err := s.persistActiveProfileConfigLocked(cfg); err != nil {
		cfg.Owners = cfg.Owners[:len(cfg.Owners)-1] // revert on failure
		return err
	}
	s.config = cfg
	return nil
}

// AddOwner adds a principal to the active profile's owner list. The interceptor
// has already confirmed the caller is an owner or privileged; the handler just
// validates and persists.
func (s *Server) AddOwner(_ context.Context, msg *proto.AddOwnerRequest) (*proto.AddOwnerResponse, error) {
	principal := msg.GetPrincipal()
	if _, ok := ipcauth.ParsePrincipal(principal); !ok {
		return nil, gstatus.Errorf(codes.InvalidArgument, "invalid owner principal %q (expected uid:/gid:/group:/sid:)", principal)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	cfg, err := s.activeConfigLocked()
	if err != nil {
		return nil, fmt.Errorf("load active profile config: %w", err)
	}
	if slices.Contains(cfg.Owners, principal) {
		return &proto.AddOwnerResponse{}, nil
	}
	cfg.Owners = append(cfg.Owners, principal)
	if err := s.persistActiveProfileConfigLocked(cfg); err != nil {
		cfg.Owners = cfg.Owners[:len(cfg.Owners)-1]
		return nil, fmt.Errorf("persist owner: %w", err)
	}
	s.config = cfg
	log.Infof("added owner %q to the active profile", principal)
	return &proto.AddOwnerResponse{}, nil
}

// ResetOwner clears the active profile's owner list (and shared flag), returning
// it to the unowned state so the next caller re-claims via trust-on-first-use.
// Privileged-only, so co-owners cannot evict each other.
func (s *Server) ResetOwner(ctx context.Context, _ *proto.ResetOwnerRequest) (*proto.ResetOwnerResponse, error) {
	id, ok := ipcauth.IdentityFromContext(ctx)
	if !ok || !id.IsPrivileged() {
		return nil, gstatus.Error(codes.PermissionDenied, "reset-owner requires root/administrator")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	cfg, err := s.activeConfigLocked()
	if err != nil {
		return nil, fmt.Errorf("load active profile config: %w", err)
	}
	cfg.Owners = nil
	cfg.Shared = false
	if err := s.persistActiveProfileConfigLocked(cfg); err != nil {
		return nil, fmt.Errorf("persist owner reset: %w", err)
	}
	s.config = cfg
	log.Infof("active profile owner list reset; next caller will re-claim (trust-on-first-use)")
	return &proto.ResetOwnerResponse{}, nil
}

// ShareProfile marks the active profile shared or unshared. The interceptor has
// already confirmed the caller is an owner or privileged.
func (s *Server) ShareProfile(_ context.Context, msg *proto.ShareProfileRequest) (*proto.ShareProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	cfg, err := s.activeConfigLocked()
	if err != nil {
		return nil, fmt.Errorf("load active profile config: %w", err)
	}
	cfg.Shared = msg.GetShared()
	if err := s.persistActiveProfileConfigLocked(cfg); err != nil {
		return nil, fmt.Errorf("persist shared flag: %w", err)
	}
	s.config = cfg
	log.Infof("active profile shared flag set to %t", msg.GetShared())
	return &proto.ShareProfileResponse{}, nil
}
