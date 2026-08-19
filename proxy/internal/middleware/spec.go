package middleware

import "time"

// Spec is the apply-time, validated representation of a per-target
// middleware configuration merged with the runtime-only fields
// compiled into the middleware implementation.
//
// The wire shape is RawConfig (JSON bytes) instead of the older
// params map[string]string. Each middleware unmarshals RawConfig into
// its own typed config struct, surfacing structural validation errors
// at construction rather than per-invocation lookups.
type Spec struct {
	ID        string
	Slot      Slot
	Version   string
	Enabled   bool
	FailMode  FailMode
	Timeout   time.Duration
	RawConfig []byte
	CanMutate bool

	// Runtime-only fields populated from the registered middleware at
	// chain build time; not sourced from proto.
	MetadataKeys         []string
	AcceptedContentTypes []string
	MutationsSupported   bool
}

// Clone returns a deep copy of the spec safe to cache across mapping
// updates.
func (s Spec) Clone() Spec {
	out := s
	if len(s.RawConfig) > 0 {
		out.RawConfig = append([]byte(nil), s.RawConfig...)
	}
	if len(s.MetadataKeys) > 0 {
		out.MetadataKeys = append([]string(nil), s.MetadataKeys...)
	}
	if len(s.AcceptedContentTypes) > 0 {
		out.AcceptedContentTypes = append([]string(nil), s.AcceptedContentTypes...)
	}
	return out
}
