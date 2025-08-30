package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/flow/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
	nbgrpc "github.com/netbirdio/netbird/util/grpc"
)

type GRPCClient struct {
	realClient proto.FlowServiceClient
	clientConn *grpc.ClientConn
	stream     proto.FlowService_EventsClient
	streamMu   sync.Mutex
}

func NewClient(addr, payload, signature string, interval time.Duration) (*GRPCClient, error) {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %w", err)
	}
	var opts []grpc.DialOption
	tlsEnabled := parsedURL.Scheme == "https"
	if tlsEnabled {
		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts,
		nbgrpc.WithCustomDialer(tlsEnabled),
		grpc.WithIdleTimeout(interval*2),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		withAuthToken(payload, signature),
		grpc.WithDefaultServiceConfig(`{"healthCheckConfig": {"serviceName": ""}}`),
	)

	conn, err := grpc.NewClient(fmt.Sprintf("%s:%s", parsedURL.Hostname(), parsedURL.Port()), opts...)
	if err != nil {
		return nil, fmt.Errorf("creating new grpc client: %w", err)
	}

	return &GRPCClient{
		realClient: proto.NewFlowServiceClient(conn),
		clientConn: conn,
	}, nil
}

func (c *GRPCClient) Close() error {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()

	c.stream = nil
	if err := c.clientConn.Close(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("close client connection: %w", err)
	}

	return nil
}

func (c *GRPCClient) Receive(ctx context.Context, interval time.Duration, msgHandler func(msg *proto.FlowEventAck) error) error {
	backOff := defaultBackoff(ctx, interval)
	operation := func() error {
		if err := c.establishStreamAndReceive(ctx, msgHandler); err != nil {
			if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
				return fmt.Errorf("receive: %w: %w", err, context.Canceled)
			}
			log.Errorf("receive failed: %v", err)
			return fmt.Errorf("receive: %w", err)
		}
		return nil
	}

	if err := backoff.Retry(operation, backOff); err != nil {
		return fmt.Errorf("receive failed permanently: %w", err)
	}

	return nil
}

func (c *GRPCClient) establishStreamAndReceive(ctx context.Context, msgHandler func(msg *proto.FlowEventAck) error) error {
	if c.clientConn.GetState() == connectivity.Shutdown {
		return errors.New("connection to flow receiver has been shut down")
	}

	stream, err := c.realClient.Events(ctx, grpc.WaitForReady(true))
	if err != nil {
		return fmt.Errorf("create event stream: %w", err)
	}

	err = stream.Send(&proto.FlowEvent{IsInitiator: true})
	if err != nil {
		log.Infof("failed to send initiator message to flow receiver but will attempt to continue. Error: %s", err)
	}

	if err = checkHeader(stream); err != nil {
		return fmt.Errorf("check header: %w", err)
	}

	c.streamMu.Lock()
	c.stream = stream
	c.streamMu.Unlock()

	return c.receive(stream, msgHandler)
}

func (c *GRPCClient) receive(stream proto.FlowService_EventsClient, msgHandler func(msg *proto.FlowEventAck) error) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("receive from stream: %w", err)
		}

		if msg.IsInitiator {
			log.Tracef("received initiator message from flow receiver")
			continue
		}

		if err := msgHandler(msg); err != nil {
			return fmt.Errorf("handle message: %w", err)
		}
	}
}

func checkHeader(stream proto.FlowService_EventsClient) error {
	header, err := stream.Header()
	if err != nil {
		log.Errorf("waiting for flow receiver header: %s", err)
		return fmt.Errorf("wait for header: %w", err)
	}

	if len(header) == 0 {
		log.Error("flow receiver sent no headers")
		return fmt.Errorf("should have headers")
	}
	return nil
}

func defaultBackoff(ctx context.Context, interval time.Duration) backoff.BackOff {
	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         interval / 2,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
}

func (c *GRPCClient) Send(event *proto.FlowEvent) error {
	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream == nil {
		return errors.New("stream not initialized")
	}

	if err := stream.Send(event); err != nil {
		return fmt.Errorf("send flow event: %w", err)
	}

	return nil
}
