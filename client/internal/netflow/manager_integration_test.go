package netflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/flow/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
)

type testServer struct {
	proto.UnimplementedFlowServiceServer
	events         chan *proto.FlowEvent
	acks           chan *proto.FlowEventAck
	grpcSrv        *grpc.Server
	addr           string
	handlerDone    chan struct{} // signaled each time Events() exits
	handlerStarted chan struct{} // signaled each time Events() begins
}

func newTestServer(t *testing.T) *testServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &testServer{
		events:         make(chan *proto.FlowEvent, 100),
		acks:           make(chan *proto.FlowEventAck, 100),
		grpcSrv:        grpc.NewServer(),
		addr:           listener.Addr().String(),
		handlerDone:    make(chan struct{}, 10),
		handlerStarted: make(chan struct{}, 10),
	}

	proto.RegisterFlowServiceServer(s.grpcSrv, s)

	go func() {
		if err := s.grpcSrv.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Logf("server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		s.grpcSrv.Stop()
	})

	return s
}

func (s *testServer) Events(stream proto.FlowService_EventsServer) error {
	defer func() {
		select {
		case s.handlerDone <- struct{}{}:
		default:
		}
	}()

	err := stream.Send(&proto.FlowEventAck{IsInitiator: true})
	if err != nil {
		return err
	}

	select {
	case s.handlerStarted <- struct{}{}:
	default:
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	go func() {
		defer cancel()
		for {
			event, err := stream.Recv()
			if err != nil {
				return
			}

			if !event.IsInitiator {
				select {
				case s.events <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case ack := <-s.acks:
			if err := stream.Send(ack); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestSendEventReceiveAck(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	server := newTestServer(t)
	manager := createManager(t, server.addr, 60*time.Second) // set high to prevent retries in this test
	defer manager.Close()

	assert.Eventually(t, func() bool {
		select {
		case <-server.handlerStarted:
			return true
		default:
			return false
		}
	}, 3*time.Second, 100*time.Millisecond)

	event1 := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		DestIP:    ipAddr("172.16.1.2"),
		DestPort:  2345,
		Protocol:  6,
	}
	manager.logger.StoreEvent(event1)
	event2 := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		DestIP:    ipAddr("172.16.1.1"),
		DestPort:  1234,
		Protocol:  6,
	}
	manager.logger.StoreEvent(event2)

	// verify the server received logged events
	serverSideEvents := make([]*proto.FlowEvent, 0)
	assert.Eventually(t, func() bool {
		select {
		case event := <-server.events:
			serverSideEvents = append(serverSideEvents, event)
			if len(serverSideEvents) == 2 {
				return true
			}
		default:
			if len(serverSideEvents) == 2 {
				return true
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)

	serverSideFlowIds := make([]uuid.UUID, 0, 2)
	slices.Values(serverSideEvents)(func(e *proto.FlowEvent) bool {
		id, err := uuid.FromBytes(e.FlowFields.FlowId)
		assert.NoError(t, err)
		serverSideFlowIds = append(serverSideFlowIds, id)
		return true
	})
	assert.ElementsMatch(t, []uuid.UUID{event1.FlowID, event2.FlowID}, serverSideFlowIds)

	// verify the manager tracks un-acked events
	unackedEvents := manager.eventsWithoutAcks.GetEvents()
	assert.Len(t, unackedEvents, 2)
	flowIds := make([]uuid.UUID, 0)
	slices.Values(unackedEvents)(func(e *types.Event) bool {
		flowIds = append(flowIds, e.FlowID)
		return true
	})
	assert.ElementsMatch(t, flowIds, []uuid.UUID{event1.FlowID, event2.FlowID})
}

// verify handling of retries:
//   - unacked events are retried
//   - when acks arrive, events are removed from the un-acked event tracker
func TestRetryEvents(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	server := newTestServer(t)
	manager := createManager(t, server.addr, time.Second) // set low to start retries sooner
	defer manager.Close()

	assert.Eventually(t, func() bool {
		select {
		case <-server.handlerStarted:
			return true
		default:
			return false
		}
	}, 3*time.Second, 100*time.Millisecond)

	event1 := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		DestIP:    ipAddr("172.16.1.2"),
		DestPort:  2345,
		Protocol:  6,
	}
	manager.logger.StoreEvent(event1)
	event2 := types.EventFields{
		FlowID:    uuid.New(),
		Type:      types.TypeStart,
		Direction: types.Ingress,
		DestIP:    ipAddr("172.16.1.1"),
		DestPort:  1234,
		Protocol:  6,
	}
	manager.logger.StoreEvent(event2)

	// verify the server received retries of logged events
	serverSideEvents := make([]*proto.FlowEvent, 0)
	func() {
		c := time.After(2500 * time.Millisecond)
		for {
			select {
			case event := <-server.events:
				serverSideEvents = append(serverSideEvents, event)
			case <-c:
				return
			}
		}
	}()
	assert.True(t, len(serverSideEvents) > 2) // must see retries

	uniqueServerSideEvents := make(map[uuid.UUID]*proto.FlowEvent)
	slices.Values(serverSideEvents)(func(e *proto.FlowEvent) bool {
		id, err := uuid.FromBytes(e.FlowFields.FlowId)
		assert.NoError(t, err)
		uniqueServerSideEvents[id] = e
		return true
	})
	assert.Contains(t, uniqueServerSideEvents, event1.FlowID)
	assert.Contains(t, uniqueServerSideEvents, event2.FlowID)

	// ack events
	server.acks <- &proto.FlowEventAck{EventId: uniqueServerSideEvents[event1.FlowID].EventId}
	server.acks <- &proto.FlowEventAck{EventId: uniqueServerSideEvents[event2.FlowID].EventId}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		unackedEvents := manager.eventsWithoutAcks.GetEvents()
		assert.Empty(c, unackedEvents)

	}, 3*time.Second, 100*time.Millisecond)
}

func createManager(t *testing.T, serverAddr string, retryInterval time.Duration) *Manager {
	t.Helper()

	mockIFace := &mockIFaceMapper{
		address: wgaddr.Address{
			Network: netip.MustParsePrefix("192.168.1.1/32"),
		},
		isUserspaceBind: true,
	}

	publicKey := []byte("test-public-key")
	manager := NewManager(mockIFace, publicKey, nil)
	manager.retryInterval = retryInterval

	initialConfig := &types.FlowConfig{
		Enabled:        true,
		URL:            fmt.Sprintf("http://%s", serverAddr),
		TokenPayload:   "initial-payload",
		TokenSignature: "initial-signature",
		Interval:       500 * time.Millisecond,
	}

	err := manager.Update(initialConfig)
	require.NoError(t, err)

	return manager
}

func ipAddr(a string) netip.Addr {
	addr, _ := netip.ParseAddr(a)
	return addr
}
