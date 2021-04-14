package relay

import (
	"fmt"
	"github.com/pion/logging"
	"github.com/pion/turn/v2"
	log "github.com/sirupsen/logrus"
	"net"
)

//Client has no doc yet
type Client struct {
	TurnC *turn.Client
	// remote peer to reply to
	peerAddr net.Addr
	// local Wireguard connection
	localWgConn net.Conn
}

func (c *Client) Close() error {
	c.TurnC.Close()
	if c.localWgConn != nil {
		err := c.localWgConn.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func NewClient(turnAddr string, user string, pwd string) (*Client, error) {
	// a local UDP proxy to forward Wireguard's packets to the relay server
	// This endpoint should be specified in the Peer's Wireguard config
	proxyConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           proxyConn,
		Username:       user,
		Password:       pwd,
		Realm:          "wiretrustee.com",
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	// Both, client and peer needs to listen to Turn packets
	err = client.Listen()

	if err != nil {
		return nil, err
	}
	log.Infof("local address %s", proxyConn.LocalAddr().String())
	return &Client{
		TurnC: client,
	}, err
}

// Start relaying packets:
// Incoming traffic from the relay sent by the other peer will be forwarded to local Wireguard
// Outgoing traffic from local Wireguard will be intercepted and forwarded back to relayed connection
// returns a relayed address (turn) to be used on the other side (peer)
func (c *Client) Start(remoteAddr string, wgPort int) (*net.UDPAddr, *net.UDPAddr, error) {

	udpRemoteAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, nil, err
	}

	// Allocate a relay socket on the TURN server
	relayConn, err := c.TurnC.Allocate()
	if err != nil {
		return nil, nil, err
	}
	// create a connection to a local Wireguard port to forward traffic to
	c.localWgConn, err = net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", +wgPort))
	if err != nil {
		return nil, nil, err
	}

	log.Infof("allocated a new relay address [%s]", relayConn.LocalAddr().String())

	// read from relay and write to local Wireguard
	c.relayPeerToLocalDst(relayConn, c.localWgConn)
	// read from local Wireguard and write to relay
	c.relayLocalDstToPeer(c.localWgConn, relayConn)

	// Punch a UDP hole for the relayConn by sending a data to the udpRemoteAddr.
	// This will trigger a TURN client to generate a permission request to the
	// TURN server. After this, packets from the IP address will be accepted by
	// the TURN server.
	_, err = relayConn.WriteTo([]byte("Hello"), udpRemoteAddr)
	if err != nil {
		return nil, nil, err
	}
	log.Infof("Punched a hole on [%s:%s]", udpRemoteAddr.IP, udpRemoteAddr.Port)

	relayAddr, err := net.ResolveUDPAddr("udp", relayConn.LocalAddr().String())
	if err != nil {
		return nil, nil, err
	}

	wgAddr, err := net.ResolveUDPAddr("udp", c.localWgConn.LocalAddr().String())
	if err != nil {
		return nil, nil, err
	}

	return relayAddr, wgAddr, nil
}

func (c *Client) relayPeerToLocalDst(relayConn net.PacketConn, localConn net.Conn) {
	go func() {
		buf := make([]byte, 1500)
		var n int
		var err error
		for {
			n, c.peerAddr, err = relayConn.ReadFrom(buf)
			if err != nil {
				// log.Warnln("Error reading from peer: ", err.Error())
				continue
			}
			n, err = localConn.Write(buf[:n])
			if err != nil {
				log.Warnln("Error writing to local destination: ", err.Error())
			}
		}
	}()
}

func (c *Client) relayLocalDstToPeer(localConn net.Conn, relayConn net.PacketConn) {
	go func() {
		buf := make([]byte, 1500)
		var n int
		var err error
		for {
			n, err = localConn.Read(buf)
			if err != nil {
				// log.Warnln("Error reading from local destination: ", err.Error())
				continue
			}
			if c.peerAddr == nil {
				log.Warnln("We didn't received any peer connection yet")
				continue
			}
			// log.Infoln("Received message from Local: ", string(buf[:n]))
			_, err = relayConn.WriteTo(buf[:n], c.peerAddr)
			if err != nil {
				log.Warnln("Error writing to peer: ", err.Error())
			}
		}
	}()
}
