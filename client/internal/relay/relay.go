package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v2"
	"github.com/pion/turn/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	nbnet "github.com/netbirdio/netbird/util/net"
)

// ProbeResult holds the info about the result of a relay probe request
type ProbeResult struct {
	URI  *stun.URI
	Err  error
	Addr string
}

// ProbeSTUN tries binding to the given STUN uri and acquiring an address
func ProbeSTUN(ctx context.Context, uri *stun.URI) (addr string, probeErr error) {
	defer func() {
		if probeErr != nil {
			log.Debugf("stun probe error from %s: %s", uri, probeErr)
		}
	}()

	net, err := stdnet.NewNet(nil)
	if err != nil {
		probeErr = fmt.Errorf("new net: %w", err)
		return
	}

	client, err := stun.DialURI(uri, &stun.DialConfig{
		Net: net,
	})
	if err != nil {
		probeErr = fmt.Errorf("dial: %w", err)
		return
	}

	defer func() {
		if err := client.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("close: %w", err)
		}
	}()

	done := make(chan struct{})
	if err = client.Start(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		if res.Error != nil {
			probeErr = fmt.Errorf("request: %w", err)
			return
		}

		var xorAddr stun.XORMappedAddress
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			probeErr = fmt.Errorf("get xor addr: %w", err)
			return
		}

		log.Debugf("stun probe received address from %s: %s", uri, xorAddr)
		addr = xorAddr.String()

		done <- struct{}{}
	}); err != nil {
		probeErr = fmt.Errorf("client: %w", err)
		return
	}

	select {
	case <-ctx.Done():
		probeErr = fmt.Errorf("stun request: %w", ctx.Err())
		return
	case <-done:
	}

	return addr, nil
}

// ProbeTURN tries allocating a session from the given TURN URI
func ProbeTURN(ctx context.Context, uri *stun.URI) (addr string, probeErr error) {
	defer func() {
		if probeErr != nil {
			log.Debugf("turn probe error from %s: %s", uri, probeErr)
		}
	}()

	turnServerAddr := fmt.Sprintf("%s:%d", uri.Host, uri.Port)

	var conn net.PacketConn
	switch uri.Proto {
	case stun.ProtoTypeUDP:
		var err error
		conn, err = nbnet.NewListener().ListenPacket(ctx, "udp", "")
		if err != nil {
			probeErr = fmt.Errorf("listen: %w", err)
			return
		}
	case stun.ProtoTypeTCP:
		tcpConn, err := nbnet.NewDialer().DialContext(ctx, "tcp", turnServerAddr)
		if err != nil {
			probeErr = fmt.Errorf("dial: %w", err)
			return
		}
		conn = turn.NewSTUNConn(tcpConn)
	default:
		probeErr = fmt.Errorf("conn: unknown proto: %s", uri.Proto)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("conn close: %w", err)
		}
	}()

	net, err := stdnet.NewNet(nil)
	if err != nil {
		probeErr = fmt.Errorf("new net: %w", err)
		return
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       uri.Username,
		Password:       uri.Password,
		Net:            net,
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		probeErr = fmt.Errorf("create client: %w", err)
		return
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		probeErr = fmt.Errorf("client listen: %w", err)
		return
	}

	relayConn, err := client.Allocate()
	if err != nil {
		probeErr = fmt.Errorf("allocate: %w", err)
		return
	}
	defer func() {
		if err := relayConn.Close(); err != nil && probeErr == nil {
			probeErr = fmt.Errorf("close relay conn: %w", err)
		}
	}()

	log.Debugf("turn probe relay address from %s: %s", uri, relayConn.LocalAddr())

	return relayConn.LocalAddr().String(), nil
}

// ProbeAll probes all given servers asynchronously and returns the results
func ProbeAll(
	ctx context.Context,
	fn func(ctx context.Context, uri *stun.URI) (addr string, probeErr error),
	relays []*stun.URI,
) []ProbeResult {
	results := make([]ProbeResult, len(relays))

	var wg sync.WaitGroup
	for i, uri := range relays {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		wg.Add(1)
		go func(res *ProbeResult, stunURI *stun.URI) {
			defer wg.Done()
			res.URI = stunURI
			res.Addr, res.Err = fn(ctx, stunURI)
		}(&results[i], uri)
	}

	wg.Wait()

	return results
}
