//go:build android

package android

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
)

// StateChangeListener receives client state notifications.
//
// OnStateChanged is a payload-free wake-up whenever the state snapshot
// changed: connection state, the run-loop status label (e.g. NeedsLogin) or
// the session deadline. It mirrors the daemon's SubscribeStatus stream
// trigger — on each signal the consumer pulls the fresh values via
// Status() / SessionExpiresAtUnix().
//
// OnSessionExpiring forwards the engine's session-expiry warnings, fired at
// sessionwatch.WarningLead before the deadline and again at FinalWarningLead
// (finalWarning true). The second one is suppressed when the user dismissed
// the first via DismissSessionWarning. The daemon turns the same events into
// its tray notification.
type StateChangeListener interface {
	OnStateChanged()
	OnSessionExpiring(expiresAtUnix int64, leadMinutes int64, finalWarning bool)
}

// Status returns the connect run-loop's status label — the same value the
// desktop daemon serves in StatusResponse.Status. "NeedsLogin" means the
// management server rejected the peer and an interactive login is required.
//
// The label is latched: the run loop keeps its status in a per-run context
// state, which a restart replaces with a fresh Idle one, so an engine restart
// (network change, always-on) would otherwise erase the fact that the peer
// still needs to log in. Only a successful interactive login or extend clears
// it — see clearLoginRequired.
func (c *Client) Status() string {
	latched, generation := c.loginRequiredState()
	if latched {
		return string(internal.StatusNeedsLogin)
	}
	cc := c.getConnectClient()
	if cc == nil {
		return string(internal.StatusIdle)
	}
	status := cc.Status()
	if status == internal.StatusNeedsLogin {
		c.latchLoginRequired(generation)
	}
	return string(status)
}

func (c *Client) loginRequiredState() (bool, uint64) {
	c.loginRequiredMu.Lock()
	defer c.loginRequiredMu.Unlock()
	return c.loginRequired, c.loginCleared
}

// latchLoginRequired records a NeedsLogin observation, unless a clear landed
// while the caller was reading the run loop's status: cc.Status() is read
// outside the lock, so a login or extend completing in that window would
// otherwise be undone by this stale observation, stranding the UI on
// "login required" over a healthy session.
func (c *Client) latchLoginRequired(observedGeneration uint64) {
	c.loginRequiredMu.Lock()
	defer c.loginRequiredMu.Unlock()
	if c.loginCleared != observedGeneration {
		return
	}
	c.loginRequired = true
}

// clearLoginRequired releases the latch after a successful interactive login
// or session extend, and invalidates any observation already in flight.
func (c *Client) clearLoginRequired() {
	c.loginRequiredMu.Lock()
	defer c.loginRequiredMu.Unlock()
	c.loginRequired = false
	c.loginCleared++
}

// SessionExpiresAtUnix returns the SSO session deadline as unix seconds, or 0
// when no deadline is known (not SSO-registered, expiry disabled, or the
// engine has not received one yet). A past value means the session expired.
// Mirror of StatusResponse.sessionExpiresAt on the desktop daemon.
func (c *Client) SessionExpiresAtUnix() int64 {
	deadline := c.recorder.GetSessionExpiresAt()
	if deadline.IsZero() {
		return 0
	}
	return deadline.Unix()
}

// SetStateChangeListener registers the state notification listener.
// Replaces any previously registered listener; remove it with
// RemoveStateChangeListener.
func (c *Client) SetStateChangeListener(listener StateChangeListener) {
	c.stateChangeMu.Lock()
	defer c.stateChangeMu.Unlock()
	c.stopStateChangeWatchLocked()
	if listener == nil {
		return
	}

	// Both subscriptions are buffered (one pending tick, ten pending events),
	// so unsubscribing is not enough to stop callbacks: the loops would drain
	// what is already queued and deliver it to a listener the caller has
	// already removed or replaced. Gate every callback on this registration's
	// own signal, which is closed before unsubscribing.
	done := make(chan struct{})
	c.stateChangeDone = done

	id, ch := c.recorder.SubscribeToStateChanges()
	c.stateChangeSubID = id
	// The channel is closed by UnsubscribeFromStateChanges, which ends the
	// goroutine. Ticks are coalesced (buffer of one), so a burst of changes
	// wakes the listener once.
	go func() {
		for range ch {
			select {
			case <-done:
				return
			default:
			}
			listener.OnStateChanged()
		}
	}()

	c.eventSub = c.recorder.SubscribeToEvents()
	go watchSessionWarnings(c.eventSub, listener, done)
}

// RemoveStateChangeListener unregisters the state notification listener.
func (c *Client) RemoveStateChangeListener() {
	c.stateChangeMu.Lock()
	defer c.stateChangeMu.Unlock()
	c.stopStateChangeWatchLocked()
}

// DismissSessionWarning records the user's "Dismiss" on the first expiry
// warning and suppresses the final one for the current deadline. A refreshed
// deadline re-arms both. No-op while the engine is not running.
func (c *Client) DismissSessionWarning() {
	cc := c.getConnectClient()
	if cc == nil {
		return
	}
	engine := cc.Engine()
	if engine == nil {
		return
	}
	engine.DismissSessionWarning()
}

// ExtendAuthSession runs the interactive SSO flow to obtain a fresh JWT and
// asks the management server to extend the session deadline. The tunnel is
// untouched: no resync, no reconnect. Async; the result arrives on the
// listener. Mirror of the daemon's RequestExtendAuthSession /
// WaitExtendAuthSession RPC pair, with URLOpener playing the "UI opens the
// browser" role.
//
// Only one flow may be in flight: the PKCE step binds a fixed loopback port,
// so a second concurrent flow would fail on that bind. Call
// CancelExtendAuthSession when the user abandons the browser.
func (c *Client) ExtendAuthSession(urlOpener URLOpener, isAndroidTV bool, resultListener ErrListener) {
	ctx, err := c.beginExtend()
	if err != nil {
		resultListener.OnError(err)
		return
	}

	go func() {
		defer c.endExtend()
		if err := c.extendAuthSession(ctx, urlOpener, isAndroidTV); err != nil {
			resultListener.OnError(err)
			return
		}
		resultListener.OnSuccess()
	}()
}

// CancelExtendAuthSession aborts an in-flight ExtendAuthSession. The tunnel is
// left alone — unlike the login flow, which cancels the whole client context
// by stopping the engine. Without this the abandoned PKCE wait keeps its
// loopback port for the full flow timeout and blocks every later attempt.
// No-op when no flow is running.
func (c *Client) CancelExtendAuthSession() {
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.extendCancel != nil {
		c.extendCancel()
	}
}

func (c *Client) stopStateChangeWatchLocked() {
	// Signal first, unsubscribe second: closing the channels only stops new
	// items, and the loops would still hand whatever is buffered to a listener
	// that is no longer registered.
	if c.stateChangeDone != nil {
		close(c.stateChangeDone)
		c.stateChangeDone = nil
	}
	if c.stateChangeSubID != "" {
		c.recorder.UnsubscribeFromStateChanges(c.stateChangeSubID)
		c.stateChangeSubID = ""
	}
	if c.eventSub != nil {
		// Closes the channel, which ends watchSessionWarnings.
		c.recorder.UnsubscribeFromEvents(c.eventSub)
		c.eventSub = nil
	}
}

// watchSessionWarnings forwards the engine's session-expiry warnings to the
// listener. The event stream also carries unrelated traffic — network-map
// updates on every sync, DNS and route errors — so everything but an
// AUTHENTICATION event carrying the session-warning marker is dropped. Exits
// when the subscription is closed by UnsubscribeFromEvents, or earlier when
// done is closed — the stream buffers up to ten events, and a deregistered
// listener must not receive the ones already queued.
func watchSessionWarnings(sub *peer.EventSubscription, listener StateChangeListener, done <-chan struct{}) {
	for ev := range sub.Events() {
		select {
		case <-done:
			return
		default:
		}
		if ev.GetCategory() != cProto.SystemEvent_AUTHENTICATION {
			continue
		}
		meta := ev.GetMetadata()
		if meta[sessionwatch.MetaSessionWarning] != "true" {
			// Other AUTHENTICATION events exist (e.g. a deadline rejected as
			// out of range); they carry no warning marker.
			continue
		}
		deadline, err := sessionwatch.ParseExpiresAt(meta[sessionwatch.MetaSessionExpiresAt])
		if err != nil {
			log.Warnf("session warning event with unparsable deadline: %v", err)
			continue
		}
		lead, err := sessionwatch.ParseLeadMinutes(meta[sessionwatch.MetaSessionLeadMinutes])
		if err != nil {
			// Informational only — the deadline above is what drives the UI.
			lead = 0
		}
		listener.OnSessionExpiring(deadline.Unix(), int64(lead),
			meta[sessionwatch.MetaSessionFinal] == "true")
	}
}

func (c *Client) beginExtend() (context.Context, error) {
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.extendCancel != nil {
		return nil, fmt.Errorf("session extend already in progress")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.extendCancel = cancel
	return ctx, nil
}

func (c *Client) endExtend() {
	c.extendMu.Lock()
	defer c.extendMu.Unlock()
	if c.extendCancel != nil {
		c.extendCancel()
		c.extendCancel = nil
	}
}

func (c *Client) extendAuthSession(ctx context.Context, urlOpener URLOpener, isAndroidTV bool) error {
	cfg, _, cc := c.stateSnapshot()
	if cfg == nil || cc == nil {
		return fmt.Errorf("engine is not running")
	}
	engine := cc.Engine()
	if engine == nil {
		return fmt.Errorf("engine is not initialized")
	}

	authClient, err := auth.NewAuth(ctx, cfg.PrivateKey, cfg.ManagementURL, cfg)
	if err != nil {
		return fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	// Passing the config path makes the flow pick up the login_hint: an extend
	// renews the session of the account already signed in, so it must not stop to
	// offer a choice.
	a := NewAuthWithConfig(ctx, cfg, c.configPathSnapshot())
	tokenInfo, err := a.foregroundGetTokenInfo(authClient, urlOpener, isAndroidTV)
	if err != nil {
		return fmt.Errorf("interactive sso login failed: %v", err)
	}

	if _, err := engine.ExtendAuthSession(ctx, tokenInfo.GetTokenToUse()); err != nil {
		return err
	}
	c.clearLoginRequired()

	go urlOpener.OnLoginSuccess()
	return nil
}
