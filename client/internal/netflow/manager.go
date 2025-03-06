package netflow

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/netflow/conntrack"
	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/flow/client"
	"github.com/netbirdio/netbird/flow/proto"
)

// Manager handles netflow tracking and logging
type Manager struct {
	mux            sync.Mutex
	logger         nftypes.FlowLogger
	flowConfig     *nftypes.FlowConfig
	conntrack      nftypes.ConnTracker
	ctx            context.Context
	receiverClient *client.GRPCClient
	publicKey      []byte
}

// NewManager creates a new netflow manager
func NewManager(ctx context.Context, iface nftypes.IFaceMapper, publicKey []byte) *Manager {
	flowLogger := logger.New(ctx)

	var ct nftypes.ConnTracker
	if runtime.GOOS == "linux" && iface != nil && !iface.IsUserspaceBind() {
		ct = conntrack.New(flowLogger, iface)
	}

	return &Manager{
		logger:    flowLogger,
		conntrack: ct,
		ctx:       ctx,
		publicKey: publicKey,
	}
}

// Update applies new flow configuration settings
func (m *Manager) Update(update *nftypes.FlowConfig) error {
	if update == nil {
		return nil
	}
	m.mux.Lock()
	defer m.mux.Unlock()
	previous := m.flowConfig
	m.flowConfig = update

	if update.Enabled {
		if m.conntrack != nil {
			if err := m.conntrack.Start(update.Counters); err != nil {
				return fmt.Errorf("start conntrack: %w", err)
			}
		}

		m.logger.Enable()
		if previous == nil || !previous.Enabled {
			flowClient, err := client.NewClient(m.flowConfig.URL, m.flowConfig.TokenPayload, m.flowConfig.TokenSignature)
			if err != nil {
				return err
			}
			log.Infof("flow client connected to %s", m.flowConfig.URL)
			m.receiverClient = flowClient
			go m.receiveACKs(update.Interval)
			go m.startSender()
		}
		return nil
	}

	if m.conntrack != nil {
		m.conntrack.Stop()
	}
	m.logger.Disable()
	if previous != nil && previous.Enabled {
		return m.receiverClient.Close()
	}

	return nil
}

// Close cleans up all resources
func (m *Manager) Close() {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.conntrack != nil {
		m.conntrack.Close()
	}
	m.logger.Close()
	if m.receiverClient != nil {
		m.receiverClient.Close()
	}
}

// GetLogger returns the flow logger
func (m *Manager) GetLogger() nftypes.FlowLogger {
	return m.logger
}

func (m *Manager) startSender() {
	ticker := time.NewTicker(m.flowConfig.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			events := m.logger.GetEvents()
			for _, event := range events {
				if err := m.send(event); err != nil {
					log.Errorf("failed to send flow event to server: %s", err)
					continue
				}
				log.Tracef("sent flow event to server: %s", event.ID)
			}
		}
	}
}

func (m *Manager) receiveACKs(interval time.Duration) {
	m.mux.Lock()
	client := m.receiverClient
	m.mux.Unlock()

	if client == nil {
		return
	}

	err := client.Receive(m.ctx, interval, func(ack *proto.FlowEventAck) error {
		log.Tracef("received flow event ack: %s", ack.EventId)
		m.logger.DeleteEvents([]string{ack.EventId})
		return nil
	})

	if err != nil {
		log.Errorf("failed to receive flow event ack failed: %s", err)
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
		EventId:   event.ID,
		Timestamp: timestamppb.New(event.Timestamp),
		PublicKey: publicKey,
		FlowFields: &proto.FlowFields{
			FlowId:    event.FlowID[:],
			RuleId:    event.RuleID,
			Type:      proto.Type(event.Type),
			Direction: proto.Direction(event.Direction),
			Protocol:  uint32(event.Protocol),
			SourceIp:  event.SourceIP.AsSlice(),
			DestIp:    event.DestIP.AsSlice(),
			RxPackets: event.RxPackets,
			TxPackets: event.TxPackets,
			RxBytes:   event.RxBytes,
			TxBytes:   event.TxBytes,
		},
	}

	if event.Protocol == nftypes.ICMP {
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
