//go:build js

package netstack

// The js/wasm build excludes the real SOCKS5 proxy: go-socks5 pulls in
// net.ListenUDP, which TinyGo's net package does not implement. The browser
// client never runs the SOCKS5 proxy (NB_NETSTACK_SKIP_PROXY is effectively the
// only path that matters), so these no-op stubs satisfy the references in
// tun.go without dragging in the dependency.

const (
	DefaultSocks5Port = 1080
)

// Proxy is a no-op SOCKS5 proxy stub for js/wasm.
type Proxy struct{}

func NewSocks5(dialer Dialer) (*Proxy, error) {
	return &Proxy{}, nil
}

func (s *Proxy) ListenAndServe(addr string) error {
	return nil
}

func (s *Proxy) Close() error {
	return nil
}
