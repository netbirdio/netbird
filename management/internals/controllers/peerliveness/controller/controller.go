package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

const sweepChunkSize = 1000

var errNotStarted = errors.New("peer liveness controller not started")

type connection struct {
	accountID string
	session   int64
}

// Controller implements peerliveness.Controller on top of a store.
type Controller struct {
	store peerliveness.Store

	// mu guards id. Connect and Disconnect hold it shared across their store call and
	// registry update, re-registration holds it exclusively, so a connection is never
	// written under an ID that is being replaced. pendingReRegister is set while the
	// registry has not been written back under the current ID.
	mu                sync.RWMutex
	id                string
	pendingReRegister bool

	registryMu sync.Mutex
	registry   map[string]connection

	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
}

// NewController returns a Controller that is idle until Start is called.
func NewController(store peerliveness.Store) *Controller {
	return &Controller{
		store:    store,
		registry: make(map[string]connection),
	}
}

// Start registers the instance under a fresh ID, sweeps dead instances once
// synchronously and then runs the heartbeat loop until ctx is done or Release is called.
func (c *Controller) Start(ctx context.Context) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()

	if c.cancel != nil {
		return errors.New("peer liveness controller already started")
	}

	hostname, _ := os.Hostname()
	id := xid.New().String()
	if err := c.store.RegisterInstance(ctx, id, hostname); err != nil {
		return fmt.Errorf("register instance: %w", err)
	}

	c.mu.Lock()
	c.id = id
	c.mu.Unlock()

	if err := c.sweep(ctx, id); err != nil {
		log.WithContext(ctx).Errorf("startup sweep of stale instances: %v", err)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.done = make(chan struct{})
	go c.run(loopCtx, c.done, time.Now())
	return nil
}

// Connect claims the peer's connection for this instance when session is newer than the
// stored one. It returns false when a newer session already owns the peer and an error
// before Start. The write goes through st, which may be bound to the caller's transaction.
func (c *Controller) Connect(ctx context.Context, st peerliveness.Store, accountID, peerID string, session int64) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.id == "" {
		return false, errNotStarted
	}

	applied, err := st.ConnectPeer(ctx, accountID, peerID, c.id, session)
	if err != nil || !applied {
		return false, err
	}

	c.registryMu.Lock()
	c.registry[peerID] = connection{accountID: accountID, session: session}
	c.registryMu.Unlock()
	return true, nil
}

// Disconnect releases the peer's connection when it still carries session. It returns
// false when a newer session owns the peer or no connection exists. The write goes
// through st, which may be bound to the caller's transaction.
func (c *Controller) Disconnect(ctx context.Context, st peerliveness.Store, peerID string, session int64) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	deleted, err := st.DisconnectPeer(ctx, peerID, session)
	if err != nil {
		return false, err
	}

	c.registryMu.Lock()
	if conn, ok := c.registry[peerID]; ok && conn.session == session {
		delete(c.registry, peerID)
	}
	c.registryMu.Unlock()
	return deleted, nil
}

// ReleaseConnection releases the peer's connection whatever its session, so no stream of
// this instance can resurrect it. The write goes through st, which may be bound to the
// caller's transaction.
func (c *Controller) ReleaseConnection(ctx context.Context, st peerliveness.Store, peerID string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if err := st.ReleasePeerConnection(ctx, peerID); err != nil {
		return err
	}

	c.ForgetPeer(peerID)
	return nil
}

// ForgetPeer drops the registry entry of a peer once it and its connection record are
// deleted, so it is not re-registered after a heartbeat lapse.
func (c *Controller) ForgetPeer(peerID string) {
	c.registryMu.Lock()
	defer c.registryMu.Unlock()

	delete(c.registry, peerID)
}

// ForgetAccount drops the registry entries of the account's peers once the account and
// its connection records are deleted, so they are not re-registered after a heartbeat lapse.
func (c *Controller) ForgetAccount(accountID string) {
	c.registryMu.Lock()
	defer c.registryMu.Unlock()

	for peerID, conn := range c.registry {
		if conn.accountID == accountID {
			delete(c.registry, peerID)
		}
	}
}

// Release stops the heartbeat loop and retires the instance on clean shutdown.
func (c *Controller) Release(ctx context.Context) error {
	c.lifecycleMu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done = nil, nil
	c.lifecycleMu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}

	id := c.InstanceID()
	if id == "" {
		return nil
	}
	if err := c.store.ReleaseInstance(ctx, id); err != nil {
		return fmt.Errorf("release instance: %w", err)
	}
	return nil
}

// InstanceID returns the current instance ID, empty before Start.
func (c *Controller) InstanceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.id
}

func (c *Controller) run(ctx context.Context, done chan<- struct{}, lastSweep time.Time) {
	defer close(done)

	ticker := time.NewTicker(nbpeer.HeartbeatInterval)
	defer ticker.Stop()

	previousOK := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		ok := c.heartbeat(ctx)
		if ok && previousOK && time.Since(lastSweep) >= nbpeer.StaleAfter {
			if err := c.sweep(ctx, c.InstanceID()); err != nil {
				log.WithContext(ctx).Errorf("sweep stale instances: %v", err)
			}
			lastSweep = time.Now()
		}
		previousOK = ok
	}
}

// heartbeat refreshes the instance row and re-registers under a new ID when the row is
// gone or stale. It returns true only when the existing row was refreshed. A failed
// re-registration of the peers is retried on every following heartbeat.
func (c *Controller) heartbeat(ctx context.Context) bool {
	alive, err := c.store.HeartbeatInstance(ctx, c.InstanceID())
	if err != nil {
		log.WithContext(ctx).Errorf("heartbeat instance: %v", err)
		return false
	}
	if alive {
		if err := c.retryReRegisterPeers(ctx); err != nil {
			log.WithContext(ctx).Errorf("retry peer re-registration: %v", err)
		}
		return true
	}

	log.WithContext(ctx).Warn("instance heartbeat lapsed, re-registering under a new ID")
	if err := c.reRegister(ctx); err != nil {
		log.WithContext(ctx).Errorf("re-register instance: %v", err)
	}
	return false
}

func (c *Controller) reRegister(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	hostname, _ := os.Hostname()
	newID := xid.New().String()
	if err := c.store.RegisterInstance(ctx, newID, hostname); err != nil {
		return fmt.Errorf("register instance: %w", err)
	}
	c.id = newID
	c.pendingReRegister = true

	return c.reRegisterPeersLocked(ctx)
}

func (c *Controller) retryReRegisterPeers(ctx context.Context) error {
	c.mu.RLock()
	pending := c.pendingReRegister
	c.mu.RUnlock()
	if !pending {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.pendingReRegister {
		return nil
	}
	return c.reRegisterPeersLocked(ctx)
}

// reRegisterPeersLocked writes the registry back under the current ID. The caller holds mu
// exclusively.
func (c *Controller) reRegisterPeersLocked(ctx context.Context) error {
	if err := c.store.ReRegisterPeers(ctx, c.id, c.sessions()); err != nil {
		return fmt.Errorf("re-register peers: %w", err)
	}
	c.pendingReRegister = false
	return nil
}

func (c *Controller) sessions() []types.PeerSession {
	c.registryMu.Lock()
	defer c.registryMu.Unlock()

	sessions := make([]types.PeerSession, 0, len(c.registry))
	for peerID, conn := range c.registry {
		sessions = append(sessions, types.PeerSession{AccountID: conn.accountID, PeerID: peerID, SessionStartedAt: conn.session})
	}
	return sessions
}

// sweep drains the connections of every stale instance except ownID and removes the
// drained instance rows. A failing instance does not stop the others.
func (c *Controller) sweep(ctx context.Context, ownID string) error {
	instances, err := c.store.ListStaleInstances(ctx)
	if err != nil {
		return fmt.Errorf("list stale instances: %w", err)
	}

	var errs []error
	for _, inst := range instances {
		if inst.ID == ownID {
			continue
		}
		if err := c.sweepInstance(ctx, inst); err != nil {
			errs = append(errs, fmt.Errorf("sweep instance %s: %w", inst.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) sweepInstance(ctx context.Context, inst nbpeer.ManagementInstance) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		swept, err := c.store.SweepInstanceChunk(ctx, inst.ID, inst.LastSeen, sweepChunkSize)
		if err != nil {
			return err
		}
		if swept == 0 {
			break
		}
	}

	if _, err := c.store.DeleteInstanceIfStale(ctx, inst.ID); err != nil {
		return err
	}
	return nil
}
