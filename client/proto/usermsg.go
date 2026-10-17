package proto

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

// UserMessageKey names a piece of user-facing SystemEvent text in a
// locale-independent form. The daemon has no notion of the user's language, so it
// publishes the key and lets each UI resolve it.
//
// The value doubles as the lookup key in the desktop UI's translation bundles
// (client/ui/i18n/locales/<code>/common.json), so renaming a constant here means
// renaming the key in every bundle. The tests in client/ui/i18n lock the two
// sides together. Keys that predate this mechanism keep their original bundle
// names so the shipped translations still apply.
type UserMessageKey string

// Message-body keys published by the daemon. Every key needs an entry in
// UserMessageTexts below and a translation in the UI bundles.
const (
	// UserMsgPanic is the CRITICAL event published from the recover() guard in
	// the connect loop.
	UserMsgPanic UserMessageKey = "event.panic"

	// UserMsgDNSRecovered and UserMsgDNSUnreachable bracket a nameserver
	// group's health transitions.
	UserMsgDNSRecovered   UserMessageKey = "event.dns.recovered"
	UserMsgDNSUnreachable UserMessageKey = "event.dns.unreachable"

	// Exit-node (default route) transitions.
	UserMsgExitNodeConnected           UserMessageKey = "event.exitNode.connected"
	UserMsgExitNodeDisconnected        UserMessageKey = "event.exitNode.disconnected"
	UserMsgExitNodeConnectionLost      UserMessageKey = "event.exitNode.connectionLost"
	UserMsgExitNodeHAChange            UserMessageKey = "event.exitNode.haChange"
	UserMsgExitNodeDisconnectedUnknown UserMessageKey = "event.exitNode.disconnectedUnknown"

	// Auto-update lifecycle. UserMsgUpdateFailed takes a {reason} argument and
	// UserMsgUpdateCompleted a {version}.
	UserMsgUpdateInstalling UserMessageKey = "event.update.installing"
	UserMsgUpdateCompleted  UserMessageKey = "event.update.completed"
	UserMsgUpdateFailed     UserMessageKey = "event.update.failed"

	// UserMsgMDMPolicyApplied reports that an MDM policy replaced the config.
	UserMsgMDMPolicyApplied UserMessageKey = "notify.mdm.policyApplied.body"

	// Session-expiry events. UserMsgSessionExpiresIn takes a {remaining}
	// argument; the "soon" variant is published when the deadline has already
	// passed by the time the warning fires.
	UserMsgSessionExpiresIn      UserMessageKey = "notify.sessionWarning.body"
	UserMsgSessionExpiresSoon    UserMessageKey = "notify.sessionWarning.bodyGeneric"
	UserMsgSessionDeadlineReject UserMessageKey = "notify.sessionDeadlineRejected.body"
)

// Notification-title keys. An event without one leaves titleKey empty and the UI
// composes a title from severity and category, which is what every event did
// before message keys existed. These carry no English fallback: a UI old enough
// to ignore titleKey already builds its own title.
const (
	TitleMDMPolicyApplied      UserMessageKey = "notify.mdm.policyApplied.title"
	TitleSessionWarning        UserMessageKey = "notify.sessionWarning.title"
	TitleSessionDeadlineReject UserMessageKey = "notify.sessionDeadlineRejected.title"
)

// UserMessageTitleKeys lists every title key a daemon can publish. It sits next
// to the constants above because the two must grow together: a title key missing
// from this slice ships untranslated, and the i18n test that would have caught it
// reads this list.
var UserMessageTitleKeys = []UserMessageKey{
	TitleMDMPolicyApplied,
	TitleSessionWarning,
	TitleSessionDeadlineReject,
}

// ArgReason, ArgVersion and ArgRemaining are the placeholder names used by the
// templates below. Producers pass them to NewUserMessage; the UI bundles use the
// same names inside {}.
const (
	ArgReason    = "reason"
	ArgVersion   = "version"
	ArgRemaining = "remaining"
)

// UserMessageTexts is the English rendering of every body key, and the source of
// the SystemEvent.userMessage fallback that the CLI and pre-messageKey UIs read.
// It must match the en bundle, which the i18n test enforces.
var UserMessageTexts = map[UserMessageKey]string{
	UserMsgPanic:                       "The NetBird service panicked. Please restart the service and submit a bug report with the client logs.",
	UserMsgDNSRecovered:                "DNS servers are reachable again.",
	UserMsgDNSUnreachable:              "Unable to reach one or more DNS servers. This might affect your ability to connect to some services.",
	UserMsgExitNodeConnected:           "Exit node connected.",
	UserMsgExitNodeDisconnected:        "Exit node disconnected.",
	UserMsgExitNodeConnectionLost:      "Exit node connection lost. Your internet access might be affected.",
	UserMsgExitNodeHAChange:            "Exit node disconnected due to high availability change.",
	UserMsgExitNodeDisconnectedUnknown: "Exit node disconnected for unknown reasons.",
	UserMsgUpdateInstalling:            "Installing update now.",
	UserMsgUpdateCompleted:             "Your NetBird client was auto-updated to version {version}.",
	UserMsgUpdateFailed:                "Auto-update failed: {reason}",
	UserMsgMDMPolicyApplied:            "Your NetBird configuration was updated by your IT policy.",
	UserMsgSessionExpiresIn:            "Your NetBird session expires in {remaining}. Click Extend now to renew.",
	UserMsgSessionExpiresSoon:          "Your NetBird session is about to expire. Click Extend now to renew.",
	UserMsgSessionDeadlineReject:       "The server sent an invalid session deadline. Please sign in again.",
}

// UserMessage is a localizable user-facing event message: a stable body key, an
// optional title key, and the placeholder values to substitute. A nil
// *UserMessage carries no user-facing text, which is how internal control events
// are published.
type UserMessage struct {
	key   UserMessageKey
	title UserMessageKey
	args  map[string]string
}

// NewUserMessage builds a UserMessage from key and flat placeholder name/value
// pairs, e.g. NewUserMessage(UserMsgUpdateCompleted, ArgVersion, "0.60.1"). An
// unpaired trailing argument is dropped.
func NewUserMessage(key UserMessageKey, args ...string) *UserMessage {
	m := &UserMessage{key: key}
	if len(args)%2 != 0 {
		log.Debugf("user message %q: placeholder args not paired: %d items, last dropped", key, len(args))
		args = args[:len(args)-1]
	}
	if len(args) > 0 {
		m.args = make(map[string]string, len(args)/2)
		for i := 0; i < len(args); i += 2 {
			m.args[args[i]] = args[i+1]
		}
	}
	return m
}

// WithTitle attaches a notification title key and returns m, so it chains onto
// NewUserMessage.
func (m *UserMessage) WithTitle(key UserMessageKey) *UserMessage {
	m.title = key
	return m
}

// Key returns the body key, or the empty key for a nil message.
func (m *UserMessage) Key() UserMessageKey {
	if m == nil {
		return ""
	}
	return m.key
}

// TitleKey returns the title key, which is empty unless WithTitle was called.
func (m *UserMessage) TitleKey() UserMessageKey {
	if m == nil {
		return ""
	}
	return m.title
}

// Args returns the placeholder values, or nil for a nil message. The map is the
// message's own and must not be mutated by the caller; it is handed straight to
// SystemEvent.messageArgs.
func (m *UserMessage) Args() map[string]string {
	if m == nil {
		return nil
	}
	return m.args
}

// Text renders the English fallback for m, with placeholders substituted. A nil
// message, or a key with no registered template, renders empty so a UI treats
// the event as carrying no user-facing text.
func (m *UserMessage) Text() string {
	if m == nil {
		return ""
	}
	tmpl, ok := UserMessageTexts[m.key]
	if !ok {
		log.Warnf("no English template for user message key %q", m.key)
		return ""
	}
	for name, value := range m.args {
		tmpl = strings.ReplaceAll(tmpl, "{"+name+"}", value)
	}
	return tmpl
}
