package conn

import (
	"github.com/pion/webrtc/v3"
	"golang.zx2c4.com/wireguard/conn"
	"net"
	"sync"
)

func (*WebRTCBind) makeReceive(dcConn *DataChannelConn) conn.ReceiveFunc {
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
	id   string
	pc   *webrtc.PeerConnection
	conn *DataChannelConn
	mu   sync.Mutex
}

func NewWebRTCBind(id string, pc *webrtc.PeerConnection) conn.Bind {
	return &WebRTCBind{
		id:   id,
		pc:   pc,
		conn: nil,
		mu:   sync.Mutex{},
	}
}

func (bind *WebRTCBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	//todo whole webrtc logic from the beginning
	//todo create peer connection, offer/answer, wait until connected

	dc, err := bind.pc.CreateDataChannel(bind.id, nil)
	if err != nil {
		return nil, 0, nil
	}

	dcConn, err := WrapDataChannel(dc)
	if err != nil {
		dc.Close()
		return nil, 0, err
	}

	bind.conn = dcConn

	fns = append(fns, bind.makeReceive(bind.conn))

	return fns, 38676, nil
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
