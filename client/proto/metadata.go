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

// SystemEvent metadata markers for daemon config-change events. The daemon
// publishes a SYSTEM-category event whenever its effective Config is
// replaced (engine spawn, Up RPC, MDM policy diff); the UI re-fetches its
// cached config/features in response and, for the MDM source, shows a
// localised toast. Producer (client/server) and consumer (client/ui) share
// these so neither duplicates the wire literals.
const (
	// MetadataTypeKey is the SystemEvent.metadata key carrying the
	// config-change event type (one of the MetadataType* values below).
	MetadataTypeKey = "type"
	// MetadataTypeConfigChanged marks a config replacement that should nudge
	// UIs to re-fetch their cached config + features. UserMessage is empty so
	// the change is silent; the source is carried in MetadataSourceKey.
	MetadataTypeConfigChanged = "config_changed"
	// MetadataTypePolicyApplied marks an MDM-policy-driven config change. The
	// daemon stamps it with a (non-localised) UserMessage; the UI suppresses
	// that and builds its own localised toast off the paired config_changed
	// event instead.
	MetadataTypePolicyApplied = "policy_applied"

	// MetadataSourceKey is the SystemEvent.metadata key carrying what
	// triggered a config_changed event (one of the MetadataSource* values).
	MetadataSourceKey = "source"
	// MetadataSourceStartup marks a config_changed from the daemon Start path.
	MetadataSourceStartup = "startup"
	// MetadataSourceUpRPC marks a config_changed from the Up RPC.
	MetadataSourceUpRPC = "up_rpc"
	// MetadataSourceMDM marks a config_changed driven by an MDM policy diff.
	MetadataSourceMDM = "mdm"
)
