package proto

// SystemEvent metadata markers. The daemon stamps these on internal control
// events it publishes over SubscribeEvents (profile-list refresh, log-level
// change); the desktop UI recognises them and acts on them instead of
// surfacing them as user-facing notifications.
//
// These live in the proto package — the shared contract both the daemon
// (client/server) and the UI (client/ui/services) already import — so producer
// and consumer reference the same constant rather than duplicating literals.
// This file is hand-written and not touched by protoc.
const (
	// MetadataKindKey is the SystemEvent.metadata key carrying the event-kind
	// marker (one of the MetadataKind* values below).
	MetadataKindKey = "kind"

	// MetadataKindProfileListChanged marks a CLI-driven profile add/remove that
	// should nudge the UI's profile views to refresh.
	MetadataKindProfileListChanged = "profile-list-changed"
	// MetadataKindLogLevelChanged marks a daemon log-level change (or the
	// per-subscription snapshot) that drives the GUI's file logging on/off.
	MetadataKindLogLevelChanged = "log-level-changed"

	// MetadataProfileKey carries the profile name for
	// MetadataKindProfileListChanged.
	MetadataProfileKey = "profile"
	// MetadataLevelKey carries the lowercase logrus level name for
	// MetadataKindLogLevelChanged.
	MetadataLevelKey = "level"
)
