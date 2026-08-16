package filedrop

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// The event kinds. Progress is not an event: live transfers are polled.
const (
	EventOffer EventKind = iota
	EventCompleted
	EventFailed
	EventWithdrawn
)

// portSignalGrace bounds how long a failed attempt waits for one signal message
// that may advertise the receiver's actual port before giving up.
const portSignalGrace = 3 * time.Second

// ErrNotConnected indicates the operation needs a running tunnel.
var ErrNotConnected = errors.New("not connected")

// EventKind classifies the events the manager surfaces to the platform layer.
type EventKind uint8

// EventSink receives transfer events. Calls may come from server goroutines.
type EventSink func(kind EventKind, transfer Transfer)

// ManagerConfig configures a per-profile file drop manager. Policy and history
// live in Store; DataDir only holds the spool of partially received files,
// which is disposable and never outlives an offer's TTL.
type ManagerConfig struct {
	Profile  profilemanager.ID
	DataDir  string
	Store    Store
	Events   EventSink
	OfferTTL time.Duration
}

type sendHandle struct {
	cancel   context.CancelFunc
	ip       netip.Addr
	addr     netip.AddrPort
	remoteID OfferID
}

// Manager owns one profile's file drop state.
type Manager struct {
	mu       sync.Mutex
	profile  profilemanager.ID
	dataDir  string
	store    Store
	policy   *PolicyStore
	history  *History
	events   EventSink
	offerTTL time.Duration

	server     *Server
	ports      *PortRegistry
	dial       DialFunc
	senderName string
	sends      map[OfferID]*sendHandle
	sendWg     sync.WaitGroup
}

// NewManager loads or initializes the file drop state for one profile.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("data dir is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create file drop dir: %w", err)
	}

	m := &Manager{
		profile:  cfg.Profile,
		dataDir:  cfg.DataDir,
		store:    cfg.Store,
		policy:   LoadPolicyStore(cfg.Profile, cfg.Store),
		history:  LoadHistory(cfg.Store),
		events:   cfg.Events,
		offerTTL: cfg.OfferTTL,
		ports:    NewPortRegistry(),
		sends:    make(map[OfferID]*sendHandle),
	}
	return m, nil
}

// Profile returns the profile this manager belongs to.
func (m *Manager) Profile() profilemanager.ID {
	return m.profile
}

// Policy returns the receiving policy store.
func (m *Manager) Policy() *PolicyStore {
	return m.policy
}

// Ports returns the registry of peer-advertised listen ports; the engine feeds it
// from incoming signal messages.
func (m *Manager) Ports() *PortRegistry {
	return m.ports
}

// ReceiverPort returns the port the receiver is actually bound to, 0 when stopped.
func (m *Manager) ReceiverPort() uint16 {
	m.mu.Lock()
	server := m.server
	m.mu.Unlock()
	if server == nil {
		return 0
	}
	return server.BoundPort()
}

// Transfers returns the history entries, newest first, with pending offers included.
func (m *Manager) Transfers() []Transfer {
	return m.history.List()
}

// DeleteTransfer removes a history entry. A live transfer is cancelled first.
func (m *Manager) DeleteTransfer(id OfferID) {
	if t, ok := m.history.Get(id); ok && !t.terminal() {
		m.Cancel(id)
	}
	m.history.Delete(id)
}

// DestinationDir returns the directory received files are delivered to.
func (m *Manager) DestinationDir() string {
	return m.policy.DestinationDir()
}

// SetDestinationDir persists the delivery directory.
func (m *Manager) SetDestinationDir(dir string) error {
	return m.policy.SetDestinationDir(dir)
}

// StartReceiver binds the receiving server on addr.
func (m *Manager) StartReceiver(ctx context.Context, addr netip.AddrPort, netstackNet *netstack.Net, resolver PeerResolver) error {
	m.mu.Lock()
	if m.server != nil {
		m.mu.Unlock()
		return errors.New("receiver is already running")
	}
	m.mu.Unlock()

	server, err := NewServer(ServerConfig{
		SpoolDir: filepath.Join(m.dataDir, "spool"),
		Policy:   m.policy,
		Resolver: resolver,
		Notifier: m,
		OfferTTL: m.offerTTL,
	})
	if err != nil {
		return fmt.Errorf("create receiver: %w", err)
	}
	if netstackNet != nil {
		server.SetNetstackNet(netstackNet)
	}

	if err := server.Start(ctx, addr); err != nil {
		return fmt.Errorf("start receiver: %w", err)
	}

	m.mu.Lock()
	m.server = server
	m.mu.Unlock()
	return nil
}

// AddReceiverListener serves the receiver on an additional address, such as IPv6.
func (m *Manager) AddReceiverListener(ctx context.Context, addr netip.AddrPort) error {
	m.mu.Lock()
	server := m.server
	m.mu.Unlock()

	if server == nil {
		return errors.New("receiver is not running")
	}
	return server.AddListener(ctx, addr)
}

// StopReceiver shuts the receiving server down and drops the tunnel dialer.
func (m *Manager) StopReceiver() error {
	m.mu.Lock()
	server := m.server
	m.server = nil
	m.dial = nil
	m.mu.Unlock()

	if server == nil {
		return nil
	}
	return server.Stop()
}

// SetTunnel gives the manager the tunnel dialer and the local sender name.
func (m *Manager) SetTunnel(dial DialFunc, senderName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dial = dial
	m.senderName = senderName
}

// Close stops the receiver and aborts every outgoing transfer.
func (m *Manager) Close() error {
	err := m.StopReceiver()

	m.mu.Lock()
	for _, h := range m.sends {
		h.cancel()
	}
	m.mu.Unlock()

	m.sendWg.Wait()
	return err
}

// Send starts an asynchronous transfer and returns its local transfer ID.
func (m *Manager) Send(peer PeerKey, peerName string, addr netip.Addr, payloads []Payload) (OfferID, error) {
	if len(payloads) == 0 {
		return "", fmt.Errorf("%w: no payloads", ErrInvalidOffer)
	}

	m.mu.Lock()
	dial, senderName := m.dial, m.senderName
	m.mu.Unlock()
	if dial == nil {
		return "", ErrNotConnected
	}

	client, err := NewClient(ClientConfig{Dial: dial, SenderName: senderName, OfferTimeout: m.offerTTL})
	if err != nil {
		return "", err
	}

	id := OfferID(uuid.NewString())
	ctx, cancel := context.WithCancel(context.Background())
	handle := &sendHandle{cancel: cancel, ip: addr}

	m.mu.Lock()
	m.sends[id] = handle
	m.mu.Unlock()

	transfer := Transfer{
		ID:        id,
		Direction: DirectionSent,
		PeerKey:   peer,
		PeerName:  peerName,
		Files:     payloadMetas(payloads),
		State:     StatePending,
		TotalSize: payloadTotal(payloads),
		CreatedAt: time.Now(),
	}
	m.history.Upsert(transfer)

	m.sendWg.Add(1)
	go func() {
		defer m.sendWg.Done()
		defer cancel()
		m.runSend(ctx, client, handle, transfer, payloads)

		m.mu.Lock()
		delete(m.sends, id)
		m.mu.Unlock()
	}()

	return id, nil
}

// Cancel aborts a transfer in either direction.
func (m *Manager) Cancel(id OfferID) {
	m.mu.Lock()
	handle := m.sends[id]
	server := m.server
	var remoteAddr netip.AddrPort
	var remoteID OfferID
	if handle != nil {
		remoteAddr, remoteID = handle.addr, handle.remoteID
	}
	m.mu.Unlock()

	if handle != nil {
		handle.cancel()
		if remoteID != "" && remoteAddr.IsValid() {
			m.withdrawRemote(remoteAddr, remoteID)
		}
		m.finishTransfer(id, StateCancelled, "")
		return
	}

	if server != nil {
		if offer, ok := server.Offers().Decide(id, DecisionDeclined); ok {
			server.Spool().Remove(offer.ID)
		}
	}
	m.finishTransfer(id, StateCancelled, "")
}

// Accept releases a pending incoming offer for upload.
func (m *Manager) Accept(id OfferID) error {
	m.mu.Lock()
	server := m.server
	m.mu.Unlock()
	if server == nil {
		return ErrNotConnected
	}

	offer, ok := server.Offers().Decide(id, DecisionAccepted)
	if !ok {
		return ErrOfferNotFound
	}

	if offer.State == StateCompleted {
		m.OnCompleted(offer)
		return nil
	}

	m.history.SetProgress(id, 0)
	return nil
}

// Decline refuses a pending incoming offer.
func (m *Manager) Decline(id OfferID) error {
	m.mu.Lock()
	server := m.server
	m.mu.Unlock()
	if server == nil {
		return ErrNotConnected
	}

	offer, ok := server.Offers().Decide(id, DecisionDeclined)
	if !ok {
		return ErrOfferNotFound
	}

	server.Spool().Remove(offer.ID)
	m.finishTransfer(id, StateDeclined, "")
	return nil
}

// SetSenderRule records a per-sender exception.
func (m *Manager) SetSenderRule(peer PeerKey, rule SenderRule) error {
	if err := m.policy.SetSenderRule(peer, rule); err != nil {
		return err
	}
	if rule != SenderRuleBlock {
		return nil
	}

	m.mu.Lock()
	server := m.server
	m.mu.Unlock()
	if server == nil {
		return nil
	}

	for _, offer := range server.Offers().List() {
		if offer.Sender != peer || offer.Decision != DecisionPending {
			continue
		}
		if declined, ok := server.Offers().Decide(offer.ID, DecisionDeclined); ok {
			server.Spool().Remove(declined.ID)
			m.finishTransfer(declined.ID, StateDeclined, "")
			m.emit(EventWithdrawn, m.transferOf(declined.ID))
		}
	}
	return nil
}

func (m *Manager) runSend(ctx context.Context, client *Client, handle *sendHandle, transfer Transfer, payloads []Payload) {
	addr, remoteID, decision, err := m.offerWithPortRetry(ctx, client, handle, transfer.PeerKey, payloads)
	if err != nil {
		m.failSend(ctx, transfer.ID, err)
		return
	}

	decision, err = client.AwaitDecision(ctx, addr, remoteID, decision)
	if err != nil {
		m.failSend(ctx, transfer.ID, err)
		return
	}
	if err := decisionError(decision); err != nil {
		m.failSend(ctx, transfer.ID, err)
		return
	}

	m.history.SetProgress(transfer.ID, 0)

	completed := make([]int64, len(payloads))
	progress := func(index int, sent, _ int64) {
		completed[index] = sent
		var total int64
		for _, n := range completed {
			total += n
		}
		m.history.SetProgress(transfer.ID, total)
	}

	if err := client.Upload(ctx, addr, remoteID, payloads, progress); err != nil {
		m.failSend(ctx, transfer.ID, err)
		return
	}

	m.history.SetProgress(transfer.ID, transfer.TotalSize)
	m.finishTransfer(transfer.ID, StateCompleted, "")
	m.emit(EventCompleted, m.transferOf(transfer.ID))
}

// offerWithPortRetry places the offer on the last advertised port, falling back to
// the default. When the attempt fails on the transport, it waits out one signal
// message that may carry the receiver's actual port and retries there once. A port
// learned mid-attempt aborts the attempt immediately instead of letting it hang.
func (m *Manager) offerWithPortRetry(ctx context.Context, client *Client, handle *sendHandle, key PeerKey, payloads []Payload) (netip.AddrPort, OfferID, Decision, error) {
	used := m.ports.Port(key)
	addr := netip.AddrPortFrom(handle.ip, effectivePort(used))

	remoteID, decision, err := m.offerWatchingPorts(ctx, client, key, used, addr, payloads)
	if err == nil {
		m.storeRemote(handle, addr, remoteID)
		return addr, remoteID, decision, nil
	}
	if ctx.Err() != nil || !transportFailure(err) {
		return addr, remoteID, decision, err
	}

	graceCtx, cancel := context.WithTimeout(ctx, portSignalGrace)
	port, changed := m.ports.Await(graceCtx, key, used)
	cancel()
	if !changed {
		return addr, remoteID, decision, err
	}

	addr = netip.AddrPortFrom(handle.ip, effectivePort(port))
	remoteID, decision, err = client.Offer(ctx, addr, payloads)
	if err != nil {
		return addr, remoteID, decision, err
	}
	m.storeRemote(handle, addr, remoteID)
	return addr, remoteID, decision, nil
}

// offerWatchingPorts runs the offer while watching for a port advertisement that
// differs from the one in use; such an advertisement aborts the in-flight attempt.
func (m *Manager) offerWatchingPorts(ctx context.Context, client *Client, key PeerKey, used uint16, addr netip.AddrPort, payloads []Payload) (OfferID, Decision, error) {
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		if _, changed := m.ports.Await(watchCtx, key, used); changed {
			cancel()
		}
	}()

	return client.Offer(watchCtx, addr, payloads)
}

func (m *Manager) storeRemote(handle *sendHandle, addr netip.AddrPort, remoteID OfferID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	handle.addr = addr
	handle.remoteID = remoteID
}

func (m *Manager) failSend(ctx context.Context, id OfferID, err error) {
	if ctx.Err() != nil {
		m.finishTransfer(id, StateCancelled, "")
		return
	}

	state := StateFailed
	switch {
	case errors.Is(err, ErrDeclined):
		state = StateDeclined
	case errors.Is(err, ErrExpired):
		state = StateExpired
	}

	message := ""
	reason := ReasonNone
	if state == StateFailed {
		message = err.Error()
		if transportFailure(err) {
			reason = ReasonUnreachable
		}
	}
	m.finishTransferReason(id, state, message, reason)
	m.emit(EventFailed, m.transferOf(id))
}

func (m *Manager) withdrawRemote(addr netip.AddrPort, remoteID OfferID) {
	m.mu.Lock()
	dial, senderName := m.dial, m.senderName
	m.mu.Unlock()
	if dial == nil {
		return
	}

	client, err := NewClient(ClientConfig{Dial: dial, SenderName: senderName})
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Cancel(ctx, addr, remoteID); err != nil {
		log.Debugf("failed to withdraw file drop offer: %v", err)
	}
}

// OnOffer implements Notifier for the receiver server.
func (m *Manager) OnOffer(offer Offer) {
	transfer := Transfer{
		ID:        offer.ID,
		Direction: DirectionReceived,
		PeerKey:   offer.Sender,
		PeerName:  offer.SenderName,
		Files:     offer.Files,
		State:     offer.State,
		TotalSize: offer.TotalSize(),
		CreatedAt: offer.CreatedAt,
	}
	m.history.Upsert(transfer)

	if offer.Decision == DecisionPending {
		m.emit(EventOffer, transfer)
	}
	if offer.Decision == DecisionAccepted && offer.State == StateCompleted {
		m.OnCompleted(offer)
	}
}

// OnProgress implements Notifier.
func (m *Manager) OnProgress(offer Offer, index int, received int64) {
	var total int64
	for i, n := range offer.Progress {
		if i == index {
			n = received
		}
		total += n
	}
	m.history.SetProgress(offer.ID, total)
}

// OnCompleted implements Notifier.
func (m *Manager) OnCompleted(offer Offer) {
	m.mu.Lock()
	server := m.server
	m.mu.Unlock()
	if server == nil {
		return
	}

	transfer, ok := m.history.Get(offer.ID)
	if !ok || transfer.State == StateCompleted {
		return
	}

	delivered, err := deliver(server.Spool(), offer, m.policy.DestinationDir())
	if err != nil {
		log.Errorf("failed to deliver file drop payloads: %v", err)
		m.finishTransfer(offer.ID, StateFailed, err.Error())
		m.emit(EventFailed, m.transferOf(offer.ID))
		return
	}

	transfer.State = StateCompleted
	transfer.Transferred = transfer.TotalSize
	transfer.DeliveredPaths = delivered
	transfer.Error = ""
	m.history.Upsert(transfer)
	m.emit(EventCompleted, transfer)
}

// OnFailed implements Notifier.
func (m *Manager) OnFailed(offer Offer, err error) {
	if errors.Is(err, ErrExpired) {
		m.finishTransfer(offer.ID, StateExpired, "")
		m.emit(EventWithdrawn, m.transferOf(offer.ID))
		return
	}
	m.finishTransfer(offer.ID, StateFailed, err.Error())
	m.emit(EventFailed, m.transferOf(offer.ID))
}

// OnWithdrawn implements Notifier: the sender cancelled, so the consent prompt goes away.
func (m *Manager) OnWithdrawn(offer Offer) {
	m.finishTransfer(offer.ID, StateCancelled, "")
	m.emit(EventWithdrawn, m.transferOf(offer.ID))
}

func (m *Manager) finishTransfer(id OfferID, state State, message string) {
	m.finishTransferReason(id, state, message, ReasonNone)
}

func (m *Manager) finishTransferReason(id OfferID, state State, message string, reason FailureReason) {
	transfer, ok := m.history.Get(id)
	if !ok || transfer.terminal() {
		return
	}
	transfer.State = state
	transfer.Error = message
	transfer.Reason = reason
	m.history.Upsert(transfer)
}

func (m *Manager) transferOf(id OfferID) Transfer {
	t, _ := m.history.Get(id)
	return t
}

func (m *Manager) emit(kind EventKind, transfer Transfer) {
	if m.events != nil && transfer.ID != "" {
		m.events(kind, transfer)
	}
}

func payloadMetas(payloads []Payload) []FileMeta {
	metas := make([]FileMeta, len(payloads))
	for i, p := range payloads {
		metas[i] = p.Meta
	}
	return metas
}

func payloadTotal(payloads []Payload) int64 {
	var total int64
	for _, p := range payloads {
		total += p.Meta.Size
	}
	return total
}

func effectivePort(advertised uint16) uint16 {
	if advertised == 0 {
		return Port
	}
	return advertised
}

// transportFailure reports whether the offer never reached the receiver; any HTTP
// response, refusal included, proves the port right and is not retried elsewhere.
func transportFailure(err error) bool {
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
