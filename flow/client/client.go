package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/flow/proto"
	"github.com/netbirdio/netbird/util/embeddedroots"
	nbgrpc "github.com/netbirdio/netbird/util/grpc"
)

type GRPCClient struct {
	realClient proto.FlowServiceClient
	clientConn *grpc.ClientConn
	stream     proto.FlowService_EventsClient
}

func NewClient(ctx context.Context, addr, payload, signature string) (*GRPCClient, error) {

	transportOption := grpc.WithTransportCredentials(insecure.NewCredentials())
	if strings.Contains(addr, "443") {

		certPool, err := x509.SystemCertPool()
		if err != nil || certPool == nil {
			log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
			certPool = embeddedroots.Get()
		}

		transportOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs: certPool,
		}))
	}

	connCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		addr,
		transportOption,
		nbgrpc.WithCustomDialer(),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		withAuthToken(payload, signature),
	)

	if err != nil {
		return nil, fmt.Errorf("dialing with context: %s", err)
	}

	client := &GRPCClient{
		realClient: proto.NewFlowServiceClient(conn),
		clientConn: conn,
	}
	return client, nil
}

func (c *GRPCClient) Close() error {
	return c.clientConn.Close()
}

func (c *GRPCClient) Receive(ctx context.Context, msgHandler func(msg *proto.FlowEventAck) error) error {
	backOff := defaultBackoff(ctx)
	operation := func() error {
		connState := c.clientConn.GetState()
		if connState == connectivity.Shutdown {
			return backoff.Permanent(fmt.Errorf("connection to signal has been shut down"))
		}

		stream, err := c.realClient.Events(ctx, grpc.WaitForReady(true))
		if err != nil {
			return err
		}
		c.stream = stream

		err = checkHeader(stream)
		if err != nil {
			return err
		}

		return c.receive(stream, msgHandler)
	}

	err := backoff.Retry(operation, backOff)
	if err != nil {
		log.Errorf("exiting the flow receiver service connection retry loop due to the unrecoverable error: %v", err)
		return err
	}

	return nil
}

func (c *GRPCClient) receive(stream proto.FlowService_EventsClient, msgHandler func(msg *proto.FlowEventAck) error) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		if err := msgHandler(msg); err != nil {
			return err
		}
	}
}

func checkHeader(stream proto.FlowService_EventsClient) error {
	header, err := stream.Header()
	if err != nil {
		log.Errorf("waiting for flow receiver header: %s", err)
		return err
	}

	if len(header) == 0 {
		log.Error("flow receiver sent no headers")
		return fmt.Errorf("should have headers")
	}
	return nil
}

func defaultBackoff(ctx context.Context) backoff.BackOff {
	return backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     800 * time.Millisecond,
		RandomizationFactor: 1,
		Multiplier:          1.7,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)
}

func (c *GRPCClient) Send(ctx context.Context, event *proto.FlowEvent) error {
	if c.stream == nil {
		return fmt.Errorf("stream not initialized")
	}

	err := c.stream.Send(event)
	if err != nil {
		return fmt.Errorf("sending flow event: %s", err)
	}

	return nil
}
