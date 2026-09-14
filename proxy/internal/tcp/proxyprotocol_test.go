package tcp

import (
	"bufio"
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteProxyProtoV2_IPv4(t *testing.T) {
	// Set up a real TCP listener and dial to get connections with real addresses.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var serverConn net.Conn
	accepted := make(chan struct{})
	go func() {
		var err error
		serverConn, err = ln.Accept()
		if err != nil {
			t.Error("accept failed:", err)
		}
		close(accepted)
	}()

	clientConn, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	<-accepted
	defer serverConn.Close()

	// Use a pipe as the backend: write the header to one end, read from the other.
	backendRead, backendWrite := net.Pipe()
	defer backendRead.Close()
	defer backendWrite.Close()

	// serverConn is the "client" arg: RemoteAddr is the source, LocalAddr is the destination.
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeProxyProtoV2(serverConn, backendWrite)
	}()

	// Read the PROXY protocol header from the backend read side.
	header, err := proxyproto.Read(bufio.NewReader(backendRead))
	require.NoError(t, err)
	require.NotNil(t, header, "should have received a proxy protocol header")

	writeErr := <-writeDone
	require.NoError(t, writeErr)

	assert.Equal(t, byte(2), header.Version, "version should be 2")
	assert.Equal(t, proxyproto.PROXY, header.Command, "command should be PROXY")
	assert.Equal(t, proxyproto.TCPv4, header.TransportProtocol, "transport should be TCPv4")

	// serverConn.RemoteAddr() is the client's address (source in the header).
	expectedSrc := serverConn.RemoteAddr().(*net.TCPAddr)
	actualSrc := header.SourceAddr.(*net.TCPAddr)
	assert.Equal(t, expectedSrc.IP.String(), actualSrc.IP.String(), "source IP should match client remote addr")
	assert.Equal(t, expectedSrc.Port, actualSrc.Port, "source port should match client remote addr")

	// serverConn.LocalAddr() is the server's address (destination in the header).
	expectedDst := serverConn.LocalAddr().(*net.TCPAddr)
	actualDst := header.DestinationAddr.(*net.TCPAddr)
	assert.Equal(t, expectedDst.IP.String(), actualDst.IP.String(), "destination IP should match server local addr")
	assert.Equal(t, expectedDst.Port, actualDst.Port, "destination port should match server local addr")
}

func TestWriteProxyProtoV2_IPv6(t *testing.T) {
	// Set up a real TCP6 listener on loopback.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available:", err)
	}
	defer ln.Close()

	var serverConn net.Conn
	accepted := make(chan struct{})
	go func() {
		var err error
		serverConn, err = ln.Accept()
		if err != nil {
			t.Error("accept failed:", err)
		}
		close(accepted)
	}()

	clientConn, err := net.Dial("tcp6", ln.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	<-accepted
	defer serverConn.Close()

	backendRead, backendWrite := net.Pipe()
	defer backendRead.Close()
	defer backendWrite.Close()

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeProxyProtoV2(serverConn, backendWrite)
	}()

	header, err := proxyproto.Read(bufio.NewReader(backendRead))
	require.NoError(t, err)
	require.NotNil(t, header, "should have received a proxy protocol header")

	writeErr := <-writeDone
	require.NoError(t, writeErr)

	assert.Equal(t, byte(2), header.Version, "version should be 2")
	assert.Equal(t, proxyproto.PROXY, header.Command, "command should be PROXY")
	assert.Equal(t, proxyproto.TCPv6, header.TransportProtocol, "transport should be TCPv6")

	expectedSrc := serverConn.RemoteAddr().(*net.TCPAddr)
	actualSrc := header.SourceAddr.(*net.TCPAddr)
	assert.Equal(t, expectedSrc.IP.String(), actualSrc.IP.String(), "source IP should match client remote addr")
	assert.Equal(t, expectedSrc.Port, actualSrc.Port, "source port should match client remote addr")

	expectedDst := serverConn.LocalAddr().(*net.TCPAddr)
	actualDst := header.DestinationAddr.(*net.TCPAddr)
	assert.Equal(t, expectedDst.IP.String(), actualDst.IP.String(), "destination IP should match server local addr")
	assert.Equal(t, expectedDst.Port, actualDst.Port, "destination port should match server local addr")
}
