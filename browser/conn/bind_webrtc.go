package conn

import "net"
import "golang.zx2c4.com/wireguard/conn"

// WebRTCBind is an implementation of Wireguard Bind interface backed by WebRTC data channel
type WebRTCBind struct {
}

func (*WebRTCBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 0, nil
}

func (*WebRTCBind) Close() error {
	return nil
}

func (*WebRTCBind) SetMark(mark uint32) error {
	return nil
}

func (*WebRTCBind) Send(b []byte, ep conn.Endpoint) error {
	return nil
}

func (*WebRTCBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return nil, nil
}

// WebRTCEndpoint is an implementation of Wireguard's Endpoint interface backed by WebRTC
type WebRTCEndpoint struct {
}

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
