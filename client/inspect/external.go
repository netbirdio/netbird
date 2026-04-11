package inspect

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

const (
	externalDialTimeout = 10 * time.Second
)

// handleExternal forwards the connection to an external proxy.
// For TLS connections, it uses HTTP CONNECT to tunnel through the proxy.
// For HTTP connections, it rewrites the request to use the proxy.
func (p *Proxy) handleExternal(ctx context.Context, pconn *peekConn, dst netip.AddrPort) error {
	p.mu.RLock()
	proxyURL := p.config.ExternalURL
	p.mu.RUnlock()

	if proxyURL == nil {
		return fmt.Errorf("external proxy URL not configured")
	}

	switch proxyURL.Scheme {
	case "http", "https":
		return p.externalHTTPProxy(ctx, pconn, dst, proxyURL)
	case "socks5":
		return p.externalSOCKS5(ctx, pconn, dst, proxyURL)
	default:
		return fmt.Errorf("unsupported external proxy scheme: %s", proxyURL.Scheme)
	}
}

// externalHTTPProxy tunnels through an HTTP proxy using CONNECT.
func (p *Proxy) externalHTTPProxy(ctx context.Context, pconn *peekConn, dst netip.AddrPort, proxyURL *url.URL) error {
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = net.JoinHostPort(proxyAddr, "8080")
	}

	proxyConn, err := (&net.Dialer{Timeout: externalDialTimeout}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("dial external proxy %s: %w", proxyAddr, err)
	}
	defer func() {
		if err := proxyConn.Close(); err != nil {
			p.log.Debugf("close external proxy conn: %v", err)
		}
	}()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", dst.String(), dst.String())
	if proxyURL.User != nil {
		connectReq += "Proxy-Authorization: Basic " + basicAuth(proxyURL.User) + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := io.WriteString(proxyConn, connectReq); err != nil {
		return fmt.Errorf("send CONNECT to proxy: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
	if err != nil {
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		p.log.Debugf("close CONNECT resp body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return relay(ctx, pconn, proxyConn)
}

// externalSOCKS5 tunnels through a SOCKS5 proxy.
func (p *Proxy) externalSOCKS5(ctx context.Context, pconn *peekConn, dst netip.AddrPort, proxyURL *url.URL) error {
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		proxyAddr = net.JoinHostPort(proxyAddr, "1080")
	}

	proxyConn, err := (&net.Dialer{Timeout: externalDialTimeout}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("dial SOCKS5 proxy %s: %w", proxyAddr, err)
	}
	defer func() {
		if err := proxyConn.Close(); err != nil {
			p.log.Debugf("close SOCKS5 proxy conn: %v", err)
		}
	}()

	if err := socks5Handshake(proxyConn, dst, proxyURL.User); err != nil {
		return fmt.Errorf("SOCKS5 handshake: %w", err)
	}

	return relay(ctx, pconn, proxyConn)
}

// socks5Handshake performs the SOCKS5 handshake to connect through the proxy.
func socks5Handshake(conn net.Conn, dst netip.AddrPort, userinfo *url.Userinfo) error {
	needAuth := userinfo != nil

	// Greeting
	var methods []byte
	if needAuth {
		methods = []byte{0x00, 0x02} // no auth, username/password
	} else {
		methods = []byte{0x00} // no auth
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("send greeting: %w", err)
	}

	// Server method selection
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("unexpected SOCKS version: %d", methodResp[0])
	}

	// Handle authentication if selected
	if methodResp[1] == 0x02 {
		if err := socks5Auth(conn, userinfo); err != nil {
			return err
		}
	} else if methodResp[1] != 0x00 {
		return fmt.Errorf("unsupported SOCKS5 auth method: %d", methodResp[1])
	}

	// Connection request
	addr := dst.Addr()
	var addrBytes []byte
	if addr.Is4() {
		a4 := addr.As4()
		addrBytes = append([]byte{0x01}, a4[:]...) // IPv4
	} else {
		a16 := addr.As16()
		addrBytes = append([]byte{0x04}, a16[:]...) // IPv6
	}

	port := dst.Port()
	connectReq := append([]byte{0x05, 0x01, 0x00}, addrBytes...)
	connectReq = append(connectReq, byte(port>>8), byte(port))

	if _, err := conn.Write(connectReq); err != nil {
		return fmt.Errorf("send connect request: %w", err)
	}

	// Read response (minimum 10 bytes for IPv4)
	var respHeader [4]byte
	if _, err := io.ReadFull(conn, respHeader[:]); err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}
	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: status %d", respHeader[1])
	}

	// Skip bound address
	switch respHeader[3] {
	case 0x01: // IPv4
		var skip [4 + 2]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return fmt.Errorf("read SOCKS5 bound IPv4 address: %w", err)
		}
	case 0x04: // IPv6
		var skip [16 + 2]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return fmt.Errorf("read SOCKS5 bound IPv6 address: %w", err)
		}
	case 0x03: // Domain
		var dLen [1]byte
		if _, err := io.ReadFull(conn, dLen[:]); err != nil {
			return fmt.Errorf("read domain length: %w", err)
		}
		skip := make([]byte, int(dLen[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return fmt.Errorf("read SOCKS5 bound domain address: %w", err)
		}
	}

	return nil
}

func socks5Auth(conn net.Conn, userinfo *url.Userinfo) error {
	if userinfo == nil {
		return fmt.Errorf("SOCKS5 auth required but no credentials provided")
	}

	user := userinfo.Username()
	pass, _ := userinfo.Password()

	// Username/password auth (RFC 1929)
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, []byte(user)...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, []byte(pass)...)

	if _, err := conn.Write(auth); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 auth failed: status %d", resp[1])
	}

	return nil
}

func basicAuth(userinfo *url.Userinfo) string {
	user := userinfo.Username()
	pass, _ := userinfo.Password()
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
