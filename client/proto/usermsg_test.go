package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserMessageText(t *testing.T) {
	tests := []struct {
		name string
		msg  *UserMessage
		want string
	}{
		{
			name: "no placeholders",
			msg:  NewUserMessage(UserMsgExitNodeConnected),
			want: "Exit node connected.",
		},
		{
			name: "placeholder substituted",
			msg:  NewUserMessage(UserMsgUpdateCompleted, ArgVersion, "0.60.1"),
			want: "Your NetBird client was auto-updated to version 0.60.1.",
		},
		{
			// A dangling arg is a caller mistake; dropping it must still yield a
			// readable sentence rather than panicking on the wire path.
			name: "unpaired trailing arg dropped",
			msg:  NewUserMessage(UserMsgUpdateFailed, ArgReason, "disk full", "extra"),
			want: "Auto-update failed: disk full",
		},
		{
			name: "unknown key renders empty so the UI treats the event as silent",
			msg:  NewUserMessage("event.notRegistered"),
			want: "",
		},
		{
			name: "nil message carries no text",
			msg:  nil,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.msg.Text())
		})
	}
}

// A nil *UserMessage is how every internal control event is published, so the
// accessors must stay usable without a nil check at each of the ~25 call sites.
func TestNilUserMessageAccessors(t *testing.T) {
	var msg *UserMessage

	assert.Empty(t, msg.Key(), "nil message must have no body key")
	assert.Empty(t, msg.TitleKey(), "nil message must have no title key")
	assert.Nil(t, msg.Args(), "nil message must have no args")
	assert.Empty(t, msg.Text(), "nil message must render empty")
}

func TestUserMessageArgsAndTitle(t *testing.T) {
	msg := NewUserMessage(UserMsgSessionExpiresIn, ArgRemaining, "10m").
		WithTitle(TitleSessionWarning)

	assert.Equal(t, UserMsgSessionExpiresIn, msg.Key())
	assert.Equal(t, TitleSessionWarning, msg.TitleKey())
	assert.Equal(t, map[string]string{ArgRemaining: "10m"}, msg.Args())
	assert.Equal(t, "Your NetBird session expires in 10m. Click Extend now to renew.", msg.Text())
}

// Every registered template must be reachable: a key whose text is empty would
// publish an event with a key but no fallback for the CLI and older UIs.
func TestUserMessageTextsAreNonEmpty(t *testing.T) {
	texts := UserMessageTexts
	assert.NotEmpty(t, texts, "the catalog must not be empty")

	for key, text := range texts {
		assert.NotEmpty(t, text, "message key %q has an empty template", key)
		assert.NotEmpty(t, key, "the catalog must not contain an empty key")
	}
}

func TestUserMessageTitleKeysAreUnique(t *testing.T) {
	seen := make(map[UserMessageKey]struct{})
	for _, key := range UserMessageTitleKeys {
		assert.NotEmpty(t, key, "title keys must not be empty")
		_, dup := seen[key]
		assert.False(t, dup, "title key %q listed twice", key)
		seen[key] = struct{}{}
	}
}
