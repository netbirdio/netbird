package server

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// configChangeRequested reports whether applying input would move the target
// profile away from the configuration it already persists. It is the decision
// procedure of the update-settings kill switch (--disable-update-settings /
// NB_DISABLE_UPDATE_SETTINGS / the MDM DisableUpdateSettings key): that switch
// forbids *changing* settings, so a request that restates the stored values is
// not a change and must not be refused.
//
// This has to be judged on values, not on field presence. `netbird up` rebuilds
// the whole config surface of SetConfigRequest and LoginRequest from its flags
// and environment on every invocation, so a service or container configured by
// environment restates its own configuration on every start. A presence-based
// gate refused those requests, and because Login carries the same fields it
// refused the login too — leaving such a client unable to come up at all.
//
// A dry run that cannot be evaluated fails closed: the request counts as a
// change, so a malformed field can never open the gate. The error itself is
// reported to the caller by the real update path.
func configChangeRequested(stored *profilemanager.Config, input profilemanager.ConfigInput) bool {
	changed, err := stored.WouldChange(input)
	if err != nil {
		log.Warnf("cannot evaluate the requested config change, treating it as a change: %v", err)
		return true
	}
	return changed
}

// loginOverridesInput builds the ConfigInput a login request persists. The
// management URL and the pre-shared key are the only config fields the daemon
// applies from a LoginRequest; everything else on that message is either pure
// auth or ignored. An empty pre-shared key is dropped rather than written, so
// a login cannot clear the stored key by omission.
//
// Both the write (persistLoginOverrides) and the update-settings gate go
// through this builder, so the gate can neither refuse a field the write
// ignores nor miss one it applies.
func loginOverridesInput(msg *proto.LoginRequest) profilemanager.ConfigInput {
	if msg == nil {
		return profilemanager.ConfigInput{}
	}

	preSharedKey := msg.OptionalPreSharedKey
	if preSharedKey != nil && *preSharedKey == "" {
		preSharedKey = nil
	}

	return profilemanager.ConfigInput{
		ManagementURL: msg.ManagementUrl,
		PreSharedKey:  preSharedKey,
	}
}
