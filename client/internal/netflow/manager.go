package netflow

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/flow/client"
	"github.com/netbirdio/netbird/flow/proto"
)

type Manager struct {
	mux            sync.Mutex
	logger         types.FlowLogger
	flowConfig     *types.FlowConfig
	ctx            context.Context
	receiverClient *client.GRPCClient
	publicKey      []byte
}

func NewManager(ctx context.Context, publicKey string) *Manager {
	return &Manager{
		logger:    logger.New(ctx),
		ctx:       ctx,
		publicKey: []byte(publicKey),
	}
}

func (m *Manager) Update(update *types.FlowConfig) error {
	m.mux.Lock()
	defer m.mux.Unlock()
	if update == nil {
		return nil
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	previous := m.flowConfig
	m.flowConfig = update

	if update.Enabled {
		m.logger.Enable()
		if previous == nil || !previous.Enabled {
			flowClient, err := client.NewClient(m.ctx, m.flowConfig.URL, m.flowConfig.TokenPayload, m.flowConfig.TokenSignature)
			if err != nil {
				return err
			}
			log.Infof("flow client connected to %s", m.flowConfig.URL)
			m.receiverClient = flowClient
			go m.receiveACKs()
			go m.startSender()
		}
		return nil
	}

	m.logger.Disable()
	if previous != nil && previous.Enabled {
		return m.receiverClient.Close()
	}

	return nil
}

func (m *Manager) Close() {
	m.logger.Close()
}

func (m *Manager) GetLogger() types.FlowLogger {
	return m.logger
}

func (m *Manager) startSender() {
	ticker := time.NewTicker(m.flowConfig.Interval)
	for {
		select {
		case <-m.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			events := m.logger.GetEvents()
			for _, event := range events {
				log.Infof("send flow event to server: %s", event.ID)
				err := m.send(event)
				if err != nil {
					log.Errorf("send flow event to server: %s", err)
				}
			}
		}
	}
}

func (m *Manager) receiveACKs() {
	if m.receiverClient == nil {
		return
	}
	err := m.receiverClient.Receive(m.ctx, func(ack *proto.FlowEventAck) error {
		log.Infof("receive flow event ack: %s", ack.EventId)
		m.logger.DeleteEvents([]string{ack.EventId})
		return nil
	})
	if err != nil {
		log.Errorf("receive flow event ack: %s", err)
	}
}

func (m *Manager) send(event *types.Event) error {
	if m.receiverClient == nil {
		return nil
	}
	return m.receiverClient.Send(m.ctx, toProtoEvent(m.publicKey, event))
}

func toProtoEvent(publicKey []byte, event *types.Event) *proto.FlowEvent {
	protoEvent := &proto.FlowEvent{
		EventId:   event.ID,
		FlowId:    event.FlowID.String(),
		Timestamp: timestamppb.New(event.Timestamp),
		PublicKey: publicKey,
		EventFields: &proto.EventFields{
			Type:      proto.Type(event.Type),
			Direction: proto.Direction(event.Direction),
			Protocol:  uint32(event.Protocol),
			SourceIp:  event.SourceIP.AsSlice(),
			DestIp:    event.DestIP.AsSlice(),
		},
	}
	if event.Protocol == 1 {
		protoEvent.EventFields.ConnectionInfo = &proto.EventFields_IcmpInfo{
			IcmpInfo: &proto.ICMPInfo{
				IcmpType: uint32(event.ICMPType),
				IcmpCode: uint32(event.ICMPCode),
			},
		}
		return protoEvent
	}

	protoEvent.EventFields.ConnectionInfo = &proto.EventFields_PortInfo{
		PortInfo: &proto.PortInfo{
			SourcePort: uint32(event.SourcePort),
			DestPort:   uint32(event.DestPort),
		},
	}

	return protoEvent
}
