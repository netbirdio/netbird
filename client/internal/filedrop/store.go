package filedrop

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	namespacePolicy  = "filedrop"
	namespaceHistory = "filedrop-history"
)

// Store persists one profile's file drop state in namespaced sections.
type Store interface {
	Get(namespace string, v any) (bool, error)
	Put(namespace string, v any) error
}

type profileStore struct {
	prefs *profilemanager.Prefs
}

// NewProfileStore returns the store backed by the profile's preferences.
func NewProfileStore(prefs *profilemanager.Prefs) Store {
	if prefs == nil {
		return nil
	}
	return &profileStore{prefs: prefs}
}

func (s *profileStore) Get(namespace string, v any) (bool, error) {
	return s.prefs.Get(namespace, v)
}

func (s *profileStore) Put(namespace string, v any) error {
	return s.prefs.Put(namespace, v)
}

func loadSection(store Store, namespace string, v any) error {
	if store == nil {
		return nil
	}
	if _, err := store.Get(namespace, v); err != nil {
		return fmt.Errorf("load %s: %w", namespace, err)
	}
	return nil
}

func saveSection(store Store, namespace string, v any) error {
	if store == nil {
		return nil
	}
	if err := store.Put(namespace, v); err != nil {
		return fmt.Errorf("save %s: %w", namespace, err)
	}
	return nil
}
