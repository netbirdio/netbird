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

// Verify that the daemon Server implements ipcauth.ProfilePolicy.
var _ ipcauth.ProfilePolicy = (*Server)(nil)

// DaemonOwnerStore persists the daemon-wide owner set. The cmd layer implements
// it over service.json. The interface lives here to avoid an import cycle. A nil
// store means the daemon is unowned, so non-privileged callers are denied on the
// default profile.
type DaemonOwnerStore interface {
	// Load returns the persisted daemon owner principals and shared flag.
	Load() (owners []string, shared bool, err error)
	// Save persists the daemon owner principals and shared flag.
	Save(owners []string, shared bool) error
}

// SetDaemonOwnerStore installs the owner persistence backend and loads the
// current owner set into memory. Called once by cmd before serving RPCs.
func (s *Server) SetDaemonOwnerStore(store DaemonOwnerStore) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.daemonOwnerStore = store
	if store == nil {
		return
	}
	owners, shared, err := store.Load()
	if err != nil {
		log.Warnf("ownership: cannot load daemon owners, treating as unowned: %v", err)
		return
	}
	s.owners = ipcauth.Ownership{Owners: owners, Shared: shared}
	log.Infof("daemon owners loaded: %d principal(s), shared=%t", len(owners), shared)
}

// activeIsDefaultLocked reports whether the active profile is the shared default.
// The default is owned daemon-wide, every other profile by its own per-profile
// owner. Caller must hold s.mutex.
func (s *Server) activeIsDefaultLocked() (bool, error) {
	active, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return false, fmt.Errorf("get active profile: %w", err)
	}
	return active.ID == profilemanager.DefaultProfileName, nil
}

// ActiveProfileOwnership returns the ownership the interceptor gates the active
// profile against. The default profile uses the daemon-wide owner set, every
// other profile uses its own collision-free owner (isolated per user).
func (s *Server) ActiveProfileOwnership() ipcauth.Ownership {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	isDefault, err := s.activeIsDefaultLocked()
	if err != nil {
		log.Warnf("ownership: cannot determine active profile, treating as unowned: %v", err)
		return ipcauth.Ownership{}
	}
	if isDefault {
		return s.owners
	}

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
// when it has no owners and is not shared (trust-on-first-use). The default
// profile claims daemon-wide ownership via the owner store, every other profile
// claims its own per-profile owner. Returns whether id is now an owner. Concurrent
// first-callers are serialized by s.mutex.
func (s *Server) ClaimActiveProfileOwnerIfUnowned(id ipcauth.Identity) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	isDefault, err := s.activeIsDefaultLocked()
	if err != nil {
		return false, fmt.Errorf("determine active profile: %w", err)
	}
	if isDefault {
		return s.claimDaemonOwnerLocked(id)
	}

	cfg := s.config
	if cfg == nil {
		loaded, err := s.loadActiveProfileConfigLocked()
		if err != nil {
			return false, fmt.Errorf("load active profile config: %w", err)
		}
		cfg = loaded
	}

	if len(cfg.Owners) > 0 || cfg.Shared {
		return false, nil // already owned or shared
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

// claimDaemonOwnerLocked claims daemon-wide ownership for id when the daemon is
// unowned and unshared, persisting via the owner store. Caller must hold s.mutex.
func (s *Server) claimDaemonOwnerLocked(id ipcauth.Identity) (bool, error) {
	if s.daemonOwnerStore == nil {
		return false, nil // no store, cannot claim, fail closed
	}
	if len(s.owners.Owners) > 0 || s.owners.Shared {
		return false, nil // already owned or shared
	}
	principal := ipcauth.OwnerPrincipalForIdentity(id)
	if err := s.daemonOwnerStore.Save([]string{principal}, false); err != nil {
		return false, fmt.Errorf("persist daemon owner claim: %w", err)
	}
	s.owners = ipcauth.Ownership{Owners: []string{principal}}
	log.Infof("daemon ownership claimed by %s (trust-on-first-use)", id)
	return true, nil
}

// addDaemonOwnerLocked adds id's principal to the daemon owner set and persists.
// Idempotent, and a no-op for privileged callers. Caller must hold s.mutex.
func (s *Server) addDaemonOwnerLocked(id ipcauth.Identity) error {
	if id.IsPrivileged() {
		return nil
	}
	if s.daemonOwnerStore == nil {
		return fmt.Errorf("daemon owner store unavailable")
	}
	principal := ipcauth.OwnerPrincipalForIdentity(id)
	if slices.Contains(s.owners.Owners, principal) {
		return nil
	}
	next := append(slices.Clone(s.owners.Owners), principal)
	if err := s.daemonOwnerStore.Save(next, s.owners.Shared); err != nil {
		return err
	}
	s.owners.Owners = next
	return nil
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

// claimForCallerLocked adds the caller's principal to the active profile's owner
// set (if absent) and persists. No-op for privileged callers. For the default
// profile it adds to the daemon-wide owners, for any other profile it adds to
// that profile's per-profile owners. Caller must hold s.mutex.
func (s *Server) claimForCallerLocked(id ipcauth.Identity, cfg *profilemanager.Config) error {
	if id.IsPrivileged() {
		return nil
	}
	isDefault, err := s.activeIsDefaultLocked()
	if err != nil {
		return err
	}
	if isDefault {
		return s.addDaemonOwnerLocked(id)
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

// authorizeTargetProfile authorizes a caller to operate on a specific target
// profile. It MUST be called after bindCallerUsername, which enforces the legacy
// per-username-directory guard. this layers the collision-free Owners field on
// top of it:
//
//   - Privileged callers (root / elevated-admin) may operate on any profile.
//   - If the target has Owners (or is Shared), they are authoritative. This
//     disambiguates users whose sanitized usernames collide.
//   - If the target is unowned (a legacy profile predating ownership), passing
//     the username guard is sufficient and then the profile is claimed.
//
// Caller must hold s.mutex (it may persist an ownership claim).
func (s *Server) authorizeTargetProfile(ctx context.Context, target *profilemanager.Profile, claim bool) error {
	id, ok := ipcauth.IdentityFromContext(ctx)
	if !ok {
		return gstatus.Error(codes.PermissionDenied, "caller identity could not be verified")
	}
	if id.IsPrivileged() {
		return nil
	}

	// The default profile is governed by the daemon-wide owners (all owners may
	// use it), not a per-profile owner. Authorize against s.owners and never stamp.
	if target.ID == profilemanager.DefaultProfileName {
		if ipcauth.Authorize(s.owners, id, s.groupResolver) {
			return nil
		}
		return gstatus.Errorf(codes.PermissionDenied,
			"not authorized to use the default profile (caller %s is not a daemon owner)", id)
	}

	path, err := target.FilePath()
	if err != nil {
		return fmt.Errorf("resolve target profile path: %w", err)
	}
	cfg, err := profilemanager.GetConfig(path)
	if err != nil {
		return fmt.Errorf("load target profile config: %w", err)
	}

	ownership := ipcauth.Ownership{Owners: cfg.Owners, Shared: cfg.Shared}

	// Owned or shared: the Owners field is authoritative (collision-free).
	if len(ownership.Owners) > 0 || ownership.Shared {
		if ipcauth.Authorize(ownership, id, s.groupResolver) {
			return nil
		}
		return gstatus.Errorf(codes.PermissionDenied,
			"not authorized to operate on profile %q (owned by another principal)", target.Name)
	}

	// Unowned legacy profile: the username guard authorizes. Stamp the caller
	// as owner so future access is collision-free.
	if claim {
		principal := ipcauth.OwnerPrincipalForIdentity(id)
		cfg.Owners = []string{principal}
		if err := util.WriteJson(context.Background(), path, cfg); err != nil {
			return fmt.Errorf("persist profile ownership claim: %w", err)
		}
		log.Infof("profile %q (%s) claimed by %s on first access (trust-on-first-use)", target.Name, target.ID, id)
	}
	return nil
}

// AddOwner adds a principal to the daemon-wide owner set. The interceptor has
// already confirmed the caller is an owner or privileged, the handler just
// validates and persists.
func (s *Server) AddOwner(_ context.Context, msg *proto.AddOwnerRequest) (*proto.AddOwnerResponse, error) {
	principal := msg.GetPrincipal()
	if _, ok := ipcauth.ParsePrincipal(principal); !ok {
		return nil, gstatus.Errorf(codes.InvalidArgument, "invalid owner principal %q (expected uid:/gid:/group:/sid:)", principal)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.daemonOwnerStore == nil {
		return nil, gstatus.Error(codes.Unavailable, "daemon owner store unavailable")
	}
	if slices.Contains(s.owners.Owners, principal) {
		return &proto.AddOwnerResponse{}, nil
	}
	next := append(slices.Clone(s.owners.Owners), principal)
	if err := s.daemonOwnerStore.Save(next, s.owners.Shared); err != nil {
		return nil, fmt.Errorf("persist owner: %w", err)
	}
	s.owners.Owners = next
	log.Infof("added daemon owner %q", principal)
	return &proto.AddOwnerResponse{}, nil
}

// ResetOwner clears the daemon-wide owner set (and shared flag), returning the
// daemon to the unowned state so the next caller re-claims via trust-on-first-use.
// Privileged-only, so co-owners cannot evict each other.
func (s *Server) ResetOwner(ctx context.Context, _ *proto.ResetOwnerRequest) (*proto.ResetOwnerResponse, error) {
	id, ok := ipcauth.IdentityFromContext(ctx)
	if !ok || !id.IsPrivileged() {
		return nil, gstatus.Error(codes.PermissionDenied, "reset-owner requires root/administrator")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.daemonOwnerStore == nil {
		return nil, gstatus.Error(codes.Unavailable, "daemon owner store unavailable")
	}
	if err := s.daemonOwnerStore.Save(nil, false); err != nil {
		return nil, fmt.Errorf("persist owner reset: %w", err)
	}
	s.owners = ipcauth.Ownership{}
	log.Infof("daemon owner list reset, next caller will re-claim (trust-on-first-use)")
	return &proto.ResetOwnerResponse{}, nil
}

// ShareProfile marks the daemon shared or unshared. When shared, any authenticated
// local caller may control the daemon and its default profile. The interceptor has
// already confirmed the caller is an owner or privileged.
func (s *Server) ShareProfile(_ context.Context, msg *proto.ShareProfileRequest) (*proto.ShareProfileResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.daemonOwnerStore == nil {
		return nil, gstatus.Error(codes.Unavailable, "daemon owner store unavailable")
	}
	if err := s.daemonOwnerStore.Save(s.owners.Owners, msg.GetShared()); err != nil {
		return nil, fmt.Errorf("persist shared flag: %w", err)
	}
	s.owners.Shared = msg.GetShared()
	log.Infof("daemon shared flag set to %t", msg.GetShared())
	return &proto.ShareProfileResponse{}, nil
}
