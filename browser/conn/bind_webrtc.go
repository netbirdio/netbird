package conn

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pion/webrtc/v3"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/conn"
	"log"
	"net"
	"sync"
	"time"
)

func (*WebRTCBind) makeReceive(dcConn net.Conn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, err := dcConn.Read(buff)
		if err != nil {
			return 0, nil, err
		}
		addr := dcConn.RemoteAddr().(*DataChannelAddr)
		return n, (*WebRTCEndpoint)(addr), err
	}
}

// WebRTCBind is an implementation of Wireguard Bind interface backed by WebRTC data channel
type WebRTCBind struct {
	id        string
	pc        *webrtc.PeerConnection
	conn      net.Conn
	incoming  chan *webrtc.DataChannel
	mu        sync.Mutex
	signal    signal.Client
	key       string
	remoteKey string
	closeCond *Cond
	closeErr  error
}

func NewWebRTCBind(id string, signal signal.Client, pubKey string, remotePubKey string) conn.Bind {

	return &WebRTCBind{
		id:        id,
		pc:        nil,
		conn:      nil,
		signal:    signal,
		mu:        sync.Mutex{},
		key:       pubKey,
		remoteKey: remotePubKey,
		closeCond: NewCond(),
		incoming:  make(chan *webrtc.DataChannel, 1),
	}
}

// acceptDC accepts a datachannel over opened WebRTC connection and wraps it into net.Conn
// blocks until channel was successfully opened
func (bind *WebRTCBind) acceptDC() (stream net.Conn, err error) {
	for dc := range bind.incoming {
		stream, err := WrapDataChannel(dc)
		if err != nil {
			dc.Close()
			return nil, err
		}
		log.Printf("accepted datachannel connection %s", dc.Label())

		return stream, nil
	}
	return nil, context.Canceled
}

// openDC creates datachannel over opened WebRTC connection and wraps it into net.Conn
// blocks until channel was successfully opened
func (bind *WebRTCBind) openDC() (stream net.Conn, err error) {
	dc, err := bind.pc.CreateDataChannel(bind.id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open RTCDataChannel: %w", err)
	}

	stream, err = WrapDataChannel(dc)
	if err != nil {
		dc.Close()
		return nil, err
	}

	log.Printf("opened datachannel connection %s", dc.Label())
	return stream, err
}

func newPeerConnection() (*webrtc.PeerConnection, error) {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

func (bind *WebRTCBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {

	log.Printf("opening WebRTCBind connection")
	connected := NewCond()
	bind.pc, err = newPeerConnection()
	if err != nil {
		bind.pc.Close()
		return nil, 0, err
	}
	bind.pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		switch state {
		case webrtc.ICEConnectionStateConnected:
			connected.Signal()
		case webrtc.ICEConnectionStateClosed:
			log.Printf("WebRTC connection closed")
			//TODO
		}
	})

	bind.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		bind.incoming <- dc
	})

	controlling := bind.key < bind.remoteKey
	// decision who is creating an offer
	if controlling {
		_, err = bind.pc.CreateDataChannel(bind.id, nil)
		if err != nil {
			return nil, 0, err
		}

		offer, err := bind.pc.CreateOffer(nil)
		if err != nil {
			return nil, 0, err
		}

		if err := bind.pc.SetLocalDescription(offer); err != nil {
			return nil, 0, err
		}

		// Create channel that is blocked until ICE Gathering is complete
		gatherComplete := webrtc.GatheringCompletePromise(bind.pc)
		select {
		case <-gatherComplete:
		case <-bind.closeCond.C:
			return nil, 0, fmt.Errorf("closed while waiting for WebRTC candidates")
		}

		log.Printf("candidates gathered")

		err = bind.signal.Send(&proto.Message{
			Key:       bind.key,
			RemoteKey: bind.remoteKey,
			Body: &proto.Body{
				Type:    proto.Body_OFFER,
				Payload: Encode(bind.pc.LocalDescription()),
			},
		})
		if err != nil {
			return nil, 0, err
		}

		log.Printf("sent an offer to a remote peer")

		//answerCh := make(chan webrtc.SessionDescription, 1)

		go bind.signal.Receive(func(msg *proto.Message) error {
			log.Printf("received a message from %v -> %v", msg.RemoteKey, msg.Body.Payload)
			if msg.GetBody().Type == proto.Body_ANSWER {
				log.Printf("received answer %s", msg.GetBody().GetPayload())
				err := setRemoteDescription(bind.pc, msg.GetBody().GetPayload())
				if err != nil {
					log.Printf("%v", err)
					return err
				}
			}
			return nil
		})

	} else {
		gatherComplete := webrtc.GatheringCompletePromise(bind.pc)

		go bind.signal.Receive(func(msg *proto.Message) error {
			log.Printf("received a message from %v -> %v", msg.RemoteKey, msg.Body.Payload)
			if msg.GetBody().Type == proto.Body_OFFER {
				log.Printf("received offer %s", msg.GetBody().GetPayload())

				err = setRemoteDescription(bind.pc, msg.GetBody().GetPayload())
				if err != nil {
					log.Printf("%v", err)
					return err
				}

				sdp, err := bind.pc.CreateAnswer(nil)
				if err != nil {
					log.Printf("%v", err)
					return err
				}

				if err := bind.pc.SetLocalDescription(sdp); err != nil {
					log.Printf("%v", err)
					return err
				}

				select {
				case <-gatherComplete:
				case <-bind.closeCond.C:
					return nil
				}

				log.Printf("candidates gathered")

				err = bind.signal.Send(&proto.Message{
					Key:       bind.key,
					RemoteKey: bind.remoteKey,
					Body: &proto.Body{
						Type:    proto.Body_ANSWER,
						Payload: Encode(bind.pc.LocalDescription()),
					},
				})
				if err != nil {
					return err
				}

				log.Printf("sent an answer to a remote peer")
			}
			return nil
		})
	}

	select {
	case <-time.After(30 * time.Second):
		return nil, 0, fmt.Errorf("failed to connect in time: %w", err)
	case <-connected.C:
	}
	log.Printf("WebRTC connection has opened successfully")

	//once WebRTC has been established we can now create a datachannel and resume
	var dcConn net.Conn
	if controlling {
		dcConn, err = bind.openDC()
		if err != nil {
			return nil, 0, err
		}
	} else {
		dcConn, err = bind.acceptDC()
		if err != nil {
			return nil, 0, err
		}
	}
	bind.conn = dcConn
	fns = append(fns, bind.makeReceive(bind.conn))
	return fns, 38676, nil

}

/*func (bind *WebRTCBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {

	log.Printf("OPEN 1------")

	controlling := bind.key > bind.remoteKey

	bind.mu.Lock()
	defer bind.mu.Unlock()

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, 0, err
	}
	bind.pc = pc

	log.Printf("OPEN 2------")

	log.Printf("OPEN 3------")

	var sdp webrtc.SessionDescription
	var dc *webrtc.DataChannel
	if controlling {
		// Create offer
		sdp, err = pc.CreateOffer(nil)
		if err != nil {
			return nil, 0, err
		}
		if err := pc.SetLocalDescription(sdp); err != nil {
			return nil, 0, err
		}

		dc, err = pc.CreateDataChannel(bind.id, nil)
		if err != nil {
			return nil, 0, err
		}
	} else {
		dcConn, err := WrapDataChannel(dc)
		if err != nil {
			dc.Close()
			return nil, 0, err
		}
	}

	go bind.signal.Receive(func(msg *proto.Message) error {
		log.Printf("received a message from %v -> %v", msg.RemoteKey, msg.Body.Payload)
		switch msg.GetBody().Type {
		case proto.Body_OFFER:

			log.Printf("received offer %s", msg.GetBody().GetPayload())

			err = setRemoteDescription(pc, msg.GetBody().GetPayload())
			if err != nil {
				log.Printf("%v", err)
				return err
			}

			sdp, err := pc.CreateAnswer(nil)
			if err != nil {
				log.Printf("%v", err)
				return err
			}
			if err := pc.SetLocalDescription(sdp); err != nil {
				log.Printf("%v", err)
				return err
			}
			break
		case proto.Body_ANSWER:

			log.Printf("received answer %s", msg.GetBody().GetPayload())

			err = setRemoteDescription(pc, msg.GetBody().GetPayload())
			if err != nil {
				log.Printf("%v", err)
				return err
			}
			break
		case proto.Body_CANDIDATE:
			log.Printf("received candidate %s", msg.GetBody().GetPayload())
		}
		return nil
	})

	// Add handlers for setting up the connection.
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		fmt.Println(fmt.Sprint(state))
	})
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			if controlling {
				bind.signal.Send(&proto.Message{
					Key:       bind.key,
					RemoteKey: bind.remoteKey,
					Body: &proto.Body{
						Type:    proto.Body_OFFER,
						Payload: Encode(pc.LocalDescription()),
					},
				})
			}
		}
	})

	log.Printf("OPEN 4------")

	// blocks until channel is open
	dcConn, err := WrapDataChannel(dc)
	if err != nil {
		dc.Close()
		return nil, 0, err
	}

	bind.conn = dcConn

	fns = append(fns, bind.makeReceive(bind.conn))

	log.Printf("OPEN 5------")

	return fns, 38676, nil
}*/

func setRemoteDescription(pc *webrtc.PeerConnection, payload string) error {
	descr, err := Decode(payload)
	if err != nil {
		return err
	}
	err = pc.SetRemoteDescription(*descr)
	if err != nil {
		return err
	}

	log.Printf("parsed SDP %s", descr.SDP)

	return nil
}
func Decode(in string) (*webrtc.SessionDescription, error) {
	descr := &webrtc.SessionDescription{}
	err := json.Unmarshal([]byte(in), descr)
	if err != nil {
		return nil, err
	}

	return descr, nil
}

func Encode(obj interface{}) string {
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func (*WebRTCBind) Close() error {
	return nil
}

func (*WebRTCBind) SetMark(mark uint32) error {
	return nil
}

func (bind *WebRTCBind) Send(b []byte, ep conn.Endpoint) error {
	_, err := bind.conn.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func (*WebRTCBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return nil, nil
}

// WebRTCEndpoint is an implementation of Wireguard's Endpoint interface backed by WebRTC
type WebRTCEndpoint DataChannelAddr

func (*WebRTCEndpoint) ClearSrc() {

}
func (*WebRTCEndpoint) SrcToString() string {
	return ""
}
func (*WebRTCEndpoint) DstToString() string {
	return ""
}
func (*WebRTCEndpoint) DstToBytes() []byte {
	return nil
}
func (*WebRTCEndpoint) DstIP() net.IP {
	return nil
}
func (*WebRTCEndpoint) SrcIP() net.IP {
	return nil
}
