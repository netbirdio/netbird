package filedrop

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	SenderRuleDefault SenderRule = iota
	SenderRuleAlwaysAccept
	SenderRuleBlock
)

// SenderRule is a per-sender override on top of the base mode.
type SenderRule uint8

// Policy is the device-local receiving policy of one profile. An empty
// DestinationDir means the platform's default download directory.
type Policy struct {
	Mode           Mode                   `json:"mode"`
	Senders        map[PeerKey]SenderRule `json:"senders,omitempty"`
	DestinationDir string                 `json:"destinationDir,omitempty"`
}

// PolicyStore holds the receiving policy of one profile and evaluates it per sender.
type PolicyStore struct {
	mu      sync.RWMutex
	profile profilemanager.ID
	policy  Policy
	store   Store
}

// NewPolicyStore returns an in-memory store seeded with the default policy.
func NewPolicyStore(profile profilemanager.ID) *PolicyStore {
	return &PolicyStore{profile: profile, policy: DefaultPolicy()}
}

// LoadPolicyStore builds a store from the persisted policy of one profile.
func LoadPolicyStore(profile profilemanager.ID, store Store) *PolicyStore {
	s := &PolicyStore{
		profile: profile,
		policy:  DefaultPolicy(),
		store:   store,
	}
	if store == nil {
		return s
	}

	policy := DefaultPolicy()
	if err := loadSection(store, namespacePolicy, &policy); err != nil {
		log.Warnf("failed to load file drop policy for profile %s, using defaults: %v", profile, err)
		return s
	}
	if err := policy.validate(); err != nil {
		log.Warnf("stored file drop policy for profile %s is invalid, using defaults: %v", profile, err)
		return s
	}

	s.policy = policy.normalized()
	return s
}

// String implements fmt.Stringer.
func (r SenderRule) String() string {
	switch r {
	case SenderRuleDefault:
		return "default"
	case SenderRuleAlwaysAccept:
		return "always"
	case SenderRuleBlock:
		return "block"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

func (p Policy) validate() error {
	if !p.Mode.valid() {
		return fmt.Errorf("invalid mode %s", p.Mode)
	}
	return nil
}

func (p Policy) normalized() Policy {
	c := p.clone()
	if c.Senders == nil {
		c.Senders = map[PeerKey]SenderRule{}
	}
	return c
}

func (p Policy) clone() Policy {
	c := p
	c.Senders = make(map[PeerKey]SenderRule, len(p.Senders))
	for k, v := range p.Senders {
		c.Senders[k] = v
	}
	return c
}

// Profile returns the profile this policy belongs to.
func (s *PolicyStore) Profile() profilemanager.ID {
	return s.profile
}

// Get returns a copy of the current policy.
func (s *PolicyStore) Get() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.clone()
}

// Set replaces the policy and persists it.
func (s *PolicyStore) Set(p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}

	s.mu.Lock()
	s.policy = p.normalized()
	store, stored := s.store, s.policy.clone()
	s.mu.Unlock()

	return saveSection(store, namespacePolicy, stored)
}

// SetMode changes the base mode, leaving per-sender rules untouched.
func (s *PolicyStore) SetMode(m Mode) error {
	if !m.valid() {
		return fmt.Errorf("invalid mode %s", m)
	}

	s.mu.Lock()
	s.policy.Mode = m
	store, stored := s.store, s.policy.clone()
	s.mu.Unlock()

	return saveSection(store, namespacePolicy, stored)
}

// SetSenderRule sets or clears the override for a single sender.
func (s *PolicyStore) SetSenderRule(key PeerKey, rule SenderRule) error {
	s.mu.Lock()
	if rule == SenderRuleDefault {
		delete(s.policy.Senders, key)
	} else {
		if s.policy.Senders == nil {
			s.policy.Senders = map[PeerKey]SenderRule{}
		}
		s.policy.Senders[key] = rule
	}
	store, stored := s.store, s.policy.clone()
	s.mu.Unlock()

	return saveSection(store, namespacePolicy, stored)
}

// DestinationDir returns the directory received files are delivered to.
func (s *PolicyStore) DestinationDir() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.DestinationDir
}

// SetDestinationDir persists the delivery directory.
func (s *PolicyStore) SetDestinationDir(dir string) error {
	s.mu.Lock()
	s.policy.DestinationDir = dir
	store, stored := s.store, s.policy.clone()
	s.mu.Unlock()

	return saveSection(store, namespacePolicy, stored)
}

// Evaluate returns the mode that applies to one sender, denying on unknown values.
func (s *PolicyStore) Evaluate(key PeerKey) Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch s.policy.Senders[key] {
	case SenderRuleBlock:
		return ModeOff
	case SenderRuleAlwaysAccept:
		return ModeAutoAccept
	case SenderRuleDefault:
	default:
		return ModeOff
	}

	if !s.policy.Mode.valid() {
		return ModeOff
	}
	return s.policy.Mode
}

// DefaultPolicy asks before accepting anything, so receiving is never silently on.
func DefaultPolicy() Policy {
	return Policy{
		Mode:    ModeAsk,
		Senders: map[PeerKey]SenderRule{},
	}
}
