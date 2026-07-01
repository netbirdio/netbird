package netflow

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/netflow/conntrack"
	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/store"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/flow/client"
	"github.com/netbirdio/netbird/flow/proto"
)

// Manager handles netflow tracking and logging
type Manager struct {
	mux               sync.Mutex
	shutdownWg        sync.WaitGroup
	logger            nftypes.FlowLogger
	flowConfig        *nftypes.FlowConfig
	conntrack         nftypes.ConnTracker
	receiverClient    *client.GRPCClient
	eventsWithoutAcks nftypes.Store
	publicKey         []byte
	cancel            context.CancelFunc
	retryInterval     time.Duration
}

// NewManager creates a new netflow manager
func NewManager(iface nftypes.IFaceMapper, publicKey []byte, statusRecorder *peer.Status) *Manager {
	var prefix, prefixV6 netip.Prefix
	if iface != nil {
		prefix = iface.Address().Network
		prefixV6 = iface.Address().IPv6Net
	}
	flowLogger := logger.New(statusRecorder, prefix, prefixV6)

	var ct nftypes.ConnTracker
	if runtime.GOOS == "linux" && iface != nil && !iface.IsUserspaceBind() {
		ct = conntrack.New(flowLogger, iface)
	}

	return &Manager{
		logger:            flowLogger,
		conntrack:         ct,
		publicKey:         publicKey,
		retryInterval:     time.Second,
		eventsWithoutAcks: store.NewMemoryStore(),
	}
}

// Update applies new flow configuration settings
// needsNewClient checks if a new client needs to be created
func (m *Manager) needsNewClient(previous *nftypes.FlowConfig) bool {
	current := m.flowConfig
	return previous == nil ||
		!previous.Enabled ||
		previous.TokenPayload != current.TokenPayload ||
		previous.TokenSignature != current.TokenSignature ||
		previous.URL != current.URL
}

// enableFlow starts components for flow tracking
// must be called under m.mux lock
func (m *Manager) enableFlow(previous *nftypes.FlowConfig) error {
	// first make sender ready so events don't pile up
	if m.needsNewClient(previous) {
		if err := m.resetClient(); err != nil {
			return fmt.Errorf("reset client: %w", err)
		}
	}

	m.logger.Enable()

	if m.conntrack != nil {
		if err := m.conntrack.Start(m.flowConfig.Counters); err != nil {
			return fmt.Errorf("start conntrack: %w", err)
		}
	}

	return nil
}

// must be called under m.mux lock
func (m *Manager) resetClient() error {
	if m.receiverClient != nil {
		if err := m.receiverClient.Close(); err != nil {
			log.Warnf("error closing previous flow client: %v", err)
		}
	}

	flowClient, err := client.NewClient(m.flowConfig.URL, m.flowConfig.TokenPayload, m.flowConfig.TokenSignature, m.flowConfig.Interval)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	log.Infof("flow client configured to connect to %s", m.flowConfig.URL)

	m.receiverClient = flowClient

	if m.cancel != nil {
		m.cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	m.shutdownWg.Add(3)
	flowConfigInterval := m.flowConfig.Interval
	go func() {
		defer m.shutdownWg.Done()
		m.receiveACKs(ctx, flowClient, flowConfigInterval)
	}()
	go func() {
		defer m.shutdownWg.Done()
		m.startSender(ctx, flowConfigInterval)
	}()
	go func() {
		defer m.shutdownWg.Done()
		m.startRetries(ctx, flowConfigInterval)
	}()

	return nil
}

// disableFlow stops components for flow tracking
func (m *Manager) disableFlow() error {
	if m.cancel != nil {
		m.cancel()
	}

	if m.conntrack != nil {
		m.conntrack.Stop()
	}

	m.logger.Close()

	if m.receiverClient == nil {
		return nil
	}

	err := m.receiverClient.Close()
	m.receiverClient = nil
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// Update applies new flow configuration settings
func (m *Manager) Update(update *nftypes.FlowConfig) error {
	if update == nil {
		log.Debug("no update provided; skipping update")
		return nil
	}

	log.Tracef("updating flow configuration with new settings: url -> %s, interval -> %s, enabled? %t", update.URL, update.Interval, update.Enabled)

	m.mux.Lock()
	defer m.mux.Unlock()

	previous := m.flowConfig
	m.flowConfig = update

	// Preserve TokenPayload and TokenSignature if they were set previously
	if previous != nil && previous.TokenPayload != "" && m.flowConfig != nil && m.flowConfig.TokenPayload == "" {
		m.flowConfig.TokenPayload = previous.TokenPayload
		m.flowConfig.TokenSignature = previous.TokenSignature
	}

	m.logger.UpdateConfig(update.DNSCollection, update.ExitNodeCollection)

	changed := previous != nil && update.Enabled != previous.Enabled
	if update.Enabled {
		if changed {
			log.Infof("netflow manager enabled; starting netflow manager")
		}
		return m.enableFlow(previous)
	}

	if changed {
		log.Infof("netflow manager disabled; stopping netflow manager")
	}
	return m.disableFlow()
}

// Close cleans up all resources
func (m *Manager) Close() {
	m.mux.Lock()
	if err := m.disableFlow(); err != nil {
		log.Warnf("failed to disable flow manager: %v", err)
	}
	m.mux.Unlock()

	m.shutdownWg.Wait()
}

// GetLogger returns the flow logger
func (m *Manager) GetLogger() nftypes.FlowLogger {
	return m.logger
}

func (m *Manager) startSender(ctx context.Context, flowConfigInterval time.Duration) {
	ticker := time.NewTicker(flowConfigInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectedEvents := m.logger.ResetAggregationWindow()
			events := collectedEvents.GetAggregatedEvents()
			for _, event := range events {
				m.eventsWithoutAcks.StoreEvent(event)
				if err := m.send(event); err != nil {
					log.Errorf("failed to send flow event to server: %v", err)
				} else {
					log.Tracef("sent flow event: %s", event.ID)
				}
			}
		}
	}
}

func (m *Manager) receiveACKs(ctx context.Context, client *client.GRPCClient, flowConfigInterval time.Duration) {
	err := client.Receive(ctx, flowConfigInterval, func(ack *proto.FlowEventAck) error {
		id, err := uuid.FromBytes(ack.EventId)
		if err != nil {
			log.Warnf("failed to convert ack event id to uuid: %v", err)
			return nil
		}
		log.Tracef("received flow event ack: %s", id)
		m.eventsWithoutAcks.DeleteEvents([]uuid.UUID{id})
		return nil
	})

	if err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("failed to receive flow event ack: %v", err)
	}
}

// We effectively never drop events (see MaxInterval), which makes eventsWithoutAcks unbounded.
// We may want to limit the max size of the store, and start dropping oldest events when the threshold is reached.
func (m *Manager) startRetries(ctx context.Context, flowConfigInterval time.Duration) {
	timer := time.NewTimer(m.retryInterval)
	retryBackoff := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     1 * time.Second,
		RandomizationFactor: 0.5,
		Multiplier:          1.7,
		MaxInterval:         flowConfigInterval / 2,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			resetBackoff := true
			for _, e := range m.eventsWithoutAcks.GetEvents() {
				if e.Timestamp.Add(time.Second).After(time.Now()) {
					// grace period on retries to avoid early retries
					// do not retry if the event is less than 1 sec old
					continue
				}
				if err := m.send(e); err != nil {
					timer = time.NewTimer(retryBackoff.NextBackOff())
					resetBackoff = false
					break
				}
			}
			if resetBackoff { // use regular retry interval in absence of network errors
				retryBackoff.Reset()
				timer = time.NewTimer(m.retryInterval)
			}
		}
	}
}

func (m *Manager) send(event *nftypes.Event) error {
	m.mux.Lock()
	client := m.receiverClient
	m.mux.Unlock()

	if client == nil {
		return nil
	}

	return client.Send(toProtoEvent(m.publicKey, event))
}

func toProtoEvent(publicKey []byte, event *nftypes.Event) *proto.FlowEvent {
	protoEvent := &proto.FlowEvent{
		EventId:     event.ID[:],
		Timestamp:   timestamppb.New(event.Timestamp),
		PublicKey:   publicKey,
		WindowStart: timestamppb.New(event.WindowStart),
		WindowEnd:   timestamppb.New(event.WindowEnd),
		FlowFields: &proto.FlowFields{
			FlowId:           event.FlowID[:],
			RuleId:           event.RuleID,
			Type:             proto.Type(event.Type),
			Direction:        proto.Direction(event.Direction),
			Protocol:         uint32(event.Protocol),
			SourceIp:         event.SourceIP.AsSlice(),
			DestIp:           event.DestIP.AsSlice(),
			RxPackets:        event.RxPackets,
			TxPackets:        event.TxPackets,
			RxBytes:          event.RxBytes,
			TxBytes:          event.TxBytes,
			SourceResourceId: event.SourceResourceID,
			DestResourceId:   event.DestResourceID,
			NumOfStarts:      event.NumOfStarts,
			NumOfEnds:        event.NumOfEnds,
			NumOfDrops:       event.NumOfDrops,
		},
	}

	if event.Protocol == nftypes.ICMP || event.Protocol == nftypes.ICMPv6 {
		protoEvent.FlowFields.ConnectionInfo = &proto.FlowFields_IcmpInfo{
			IcmpInfo: &proto.ICMPInfo{
				IcmpType: uint32(event.ICMPType),
				IcmpCode: uint32(event.ICMPCode),
			},
		}
		return protoEvent
	}

	protoEvent.FlowFields.ConnectionInfo = &proto.FlowFields_PortInfo{
		PortInfo: &proto.PortInfo{
			SourcePort: uint32(event.SourcePort),
			DestPort:   uint32(event.DestPort),
		},
	}

	return protoEvent
}
