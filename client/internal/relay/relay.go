package relay

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pion/stun/v2"
	"github.com/pion/turn/v3"
	log "github.com/sirupsen/logrus"
)

type ProbeResult struct {
	URI  *stun.URI
	Err  error
	Addr string
}

func ProbeSTUN(_ context.Context, wg *sync.WaitGroup, uri *stun.URI, result *ProbeResult) {
	defer wg.Done()

	defer func() {
		if result.Err != nil {
			log.Debugf("stun probe error from %s: %s", uri, result.Err)
		}
	}()

	client, err := stun.DialURI(uri, &stun.DialConfig{})
	if err != nil {
		result.Err = fmt.Errorf("dial: %w", err)
		return
	}

	defer func() {
		if err := client.Close(); err != nil && result.Err == nil {
			result.Err = fmt.Errorf("close: %w", err)
		}
	}()

	if err = client.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		if res.Error != nil {
			result.Err = fmt.Errorf("request: %w", err)
			return
		}

		var xorAddr stun.XORMappedAddress
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			result.Err = fmt.Errorf("get xor addr: %w", err)
			return
		}

		log.Debugf("stun probe received address from %s: %s", uri, xorAddr)
		result.Addr = xorAddr.String()
	}); err != nil {
		result.Err = fmt.Errorf("client: %w", err)
		return
	}

}

func ProbeTURN(ctx context.Context, wg *sync.WaitGroup, uri *stun.URI, result *ProbeResult) {
	defer wg.Done()

	defer func() {
		if result.Err != nil {
			log.Debugf("turn probe error from %s: %s", uri, result.Err)
		}
	}()

	turnServerAddr := fmt.Sprintf("%s:%d", uri.Host, uri.Port)

	var conn net.PacketConn
	switch uri.Proto {
	case stun.ProtoTypeUDP:
		var err error
		conn, err = net.ListenPacket("udp", "")
		if err != nil {
			result.Err = fmt.Errorf("listen: %w", err)
			return
		}
	case stun.ProtoTypeTCP:
		dialer := net.Dialer{}
		tcpConn, err := dialer.DialContext(ctx, "tcp", turnServerAddr)
		if err != nil {
			result.Err = fmt.Errorf("dial: %w", err)
			return
		}
		conn = turn.NewSTUNConn(tcpConn)
	default:
		result.Err = fmt.Errorf("conn: unknown proto: %s", uri.Proto)
		return
	}

	defer func() {
		if err := conn.Close(); err != nil && result.Err == nil {
			result.Err = fmt.Errorf("conn close: %w", err)
		}
	}()

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       uri.Username,
		Password:       uri.Password,
	}
	client, err := turn.NewClient(cfg)
	if err != nil {
		result.Err = fmt.Errorf("create client: %w", err)
		return
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		result.Err = fmt.Errorf("client listen: %w", err)
		return
	}

	relayConn, err := client.Allocate()
	if err != nil {
		result.Err = fmt.Errorf("allocate: %w", err)
		return
	}
	defer func() {
		if err := relayConn.Close(); err != nil && result.Err == nil {
			result.Err = fmt.Errorf("close relay conn: %w", err)
		}
	}()

	log.Debugf("turn probe relay address from %s: %s", uri, relayConn.LocalAddr())
	result.Addr = relayConn.LocalAddr().String()
}
