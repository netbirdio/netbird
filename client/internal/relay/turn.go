package relay

import (
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/stun/v2"
	"github.com/pion/turn/v3"
	log "github.com/sirupsen/logrus"
)

type PermanentTurn struct {
	stunURI *stun.URI
	turnURI *stun.URI

	stunConn             net.PacketConn
	turnClient           *turn.Client
	turnClientListenLock sync.Mutex
	relayConn            net.PacketConn // represents the remote socket.
	srvReflexiveAddress  *net.UDPAddr
}

func NewPermanentTurn(stunURL, turnURL *stun.URI) *PermanentTurn {
	return &PermanentTurn{
		stunURI: stunURL,
		turnURI: turnURL,
	}
}

func (r *PermanentTurn) Open() error {
	log.Debugf("Opening permanent turn connection")
	stunConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	r.stunConn = stunConn

	cfg := &turn.ClientConfig{
		STUNServerAddr: toURL(r.stunURI),
		TURNServerAddr: toURL(r.turnURI),
		Conn:           stunConn,
		Username:       r.turnURI.Username,
		Password:       r.turnURI.Password,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		log.Errorf("failed to create turn client: %v", err)
		return err
	}
	r.turnClient = client
	err = r.turnClient.Listen()
	if err != nil {
		log.Errorf("failed to listen: %v", err)
	}
	//r.listen()

	relayConn, err := client.Allocate()
	if err != nil {
		log.Errorf("failed to allocate relay connection: %v", err)
		return err
	}
	r.relayConn = relayConn

	srvReflexiveAddress, err := r.discoverPublicIP()
	if err != nil {
		log.Errorf("failed to discover public IP: %v", err)
		return err
	}
	r.srvReflexiveAddress = srvReflexiveAddress
	return nil
}

func (r *PermanentTurn) RelayedAddress() net.Addr {
	return r.relayConn.LocalAddr()
}

func (r *PermanentTurn) SrvRefAddr() net.Addr {
	return r.srvReflexiveAddress
}

func (r *PermanentTurn) PunchHole(mappedAddr net.Addr) error {
	_, err := r.relayConn.WriteTo([]byte("Hello"), mappedAddr)
	return err
}

func (r *PermanentTurn) RelayConn() net.PacketConn {
	return r.relayConn
}

func (r *PermanentTurn) Close() {
	r.turnClient.Close()

	err := r.relayConn.Close()
	if err != nil {
		log.Errorf("failed to close relayConn: %s", err.Error())
	}

	err = r.stunConn.Close()
	if err != nil {
		log.Errorf("failed to close stunConn: %s", err.Error())
	}
}

func (r *PermanentTurn) discoverPublicIP() (*net.UDPAddr, error) {
	addr, err := r.turnClient.SendBindingRequest()
	if err != nil {
		log.Errorf("failed to send binding request: %v", err)
		return nil, err

	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("failed to cast addr to udp addr")
	}

	return udpAddr, nil
}

func (r *PermanentTurn) listen() {
	if !r.turnClientListenLock.TryLock() {
		return
	}

	go func() {
		defer r.turnClientListenLock.Unlock()

		buf := make([]byte, math.MaxUint16)
		for {
			n, from, err := r.stunConn.ReadFrom(buf)
			if err != nil {
				log.Errorf("Failed to read from stun conn. Exiting loop %v", err)
				break
			}

			_, err = r.turnClient.HandleInbound(buf[:n], from)
			if err != nil {
				log.Errorf("Failed to handle inbound turn message: %s. Exiting loop", err)
				break
			}
		}
	}()
}

func toURL(uri *stun.URI) string {
	return fmt.Sprintf("%s:%d", uri.Host, uri.Port)
}
