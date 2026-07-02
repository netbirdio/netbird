package upnp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<specVersion><major>1</major><minor>1</minor></specVersion>
	<device>
		<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
		<friendlyName>Test IGD</friendlyName>
		<manufacturer>test</manufacturer>
		<modelName>test</modelName>
		<UDN>uuid:test-igd</UDN>
		<deviceList>
			<device>
				<deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType>
				<friendlyName>WANDevice</friendlyName>
				<manufacturer>test</manufacturer>
				<modelName>test</modelName>
				<UDN>uuid:test-wandev</UDN>
				<deviceList>
					<device>
						<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType>
						<friendlyName>WANConnectionDevice</friendlyName>
						<manufacturer>test</manufacturer>
						<modelName>test</modelName>
						<UDN>uuid:test-wanconn</UDN>
						<serviceList>
							<service>
								<serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
								<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
								<SCPDURL>/WANIPCn.xml</SCPDURL>
								<controlURL>/ctl/IPConn</controlURL>
								<eventSubURL>/evt/IPConn</eventSubURL>
							</service>
						</serviceList>
					</device>
				</deviceList>
			</device>
		</deviceList>
	</device>
</root>`

const soapFault725 = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<s:Fault>
<faultcode>s:Client</faultcode>
<faultstring>UPnPError</faultstring>
<detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError>
</detail>
</s:Fault>
</s:Body>
</s:Envelope>`

type addPortMappingCall struct {
	body string
}

// fakeIGD emulates a MiniUPnPd-style gateway: a UDP socket answering unicast
// SSDP M-SEARCH and an HTTP server serving the device description and SOAP
// control endpoint.
type fakeIGD struct {
	t          *testing.T
	udpConn    net.PacketConn
	httpServer *httptest.Server

	// respondToST decides which search targets are answered.
	respondToST func(st string) bool
	// permanentLeaseOnly makes AddPortMapping fail with UPnP error 725
	// unless a permanent lease (duration 0) is requested.
	permanentLeaseOnly bool

	mu       sync.Mutex
	addCalls []addPortMappingCall
	delCalls []string
}

func startFakeIGD(t *testing.T, respondToST func(st string) bool, permanentLeaseOnly bool) *fakeIGD {
	t.Helper()

	f := &fakeIGD{
		t:                  t,
		respondToST:        respondToST,
		permanentLeaseOnly: permanentLeaseOnly,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
		_, _ = w.Write([]byte(rootDescXML))
	})
	mux.HandleFunc("/ctl/IPConn", f.handleSOAP)
	f.httpServer = httptest.NewServer(mux)
	t.Cleanup(f.httpServer.Close)

	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	f.udpConn = udpConn
	t.Cleanup(func() {
		_ = udpConn.Close()
	})
	go f.serveSSDP()

	return f
}

// addr returns the address unicast M-SEARCH requests should be sent to.
func (f *fakeIGD) addr() string {
	return f.udpConn.LocalAddr().String()
}

func (f *fakeIGD) serveSSDP() {
	buf := make([]byte, 2048)
	for {
		n, remote, err := f.udpConn.ReadFrom(buf)
		if err != nil {
			return
		}

		request := string(buf[:n])
		if !strings.HasPrefix(request, "M-SEARCH") {
			continue
		}

		var st string
		for line := range strings.SplitSeq(request, "\r\n") {
			if v, ok := strings.CutPrefix(line, "ST:"); ok {
				st = strings.TrimSpace(v)
			}
		}
		if !f.respondToST(st) {
			continue
		}

		response := fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"CACHE-CONTROL: max-age=1800\r\n"+
			"ST: %s\r\n"+
			"USN: uuid:test-igd::%s\r\n"+
			"EXT:\r\n"+
			"SERVER: test UPnP/1.1 MiniUPnPd/2.3.9\r\n"+
			"LOCATION: %s/rootDesc.xml\r\n"+
			"\r\n", st, st, f.httpServer.URL)
		_, _ = f.udpConn.WriteTo([]byte(response), remote)
	}
}

func (f *fakeIGD) handleSOAP(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(body)

	action := r.Header.Get("Soapaction")
	writeResponse := func(inner string) {
		w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>%s</s:Body>
</s:Envelope>`, inner)
	}

	switch {
	case strings.Contains(action, "GetNATRSIPStatus"):
		writeResponse(`<u:GetNATRSIPStatusResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewRSIPAvailable>0</NewRSIPAvailable>
<NewNATEnabled>1</NewNATEnabled>
</u:GetNATRSIPStatusResponse>`)

	case strings.Contains(action, "AddPortMapping"):
		if f.permanentLeaseOnly && !strings.Contains(string(body), "<NewLeaseDuration>0</NewLeaseDuration>") {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(soapFault725))
			return
		}
		f.mu.Lock()
		f.addCalls = append(f.addCalls, addPortMappingCall{body: string(body)})
		f.mu.Unlock()
		writeResponse(`<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"/>`)

	case strings.Contains(action, "DeletePortMapping"):
		f.mu.Lock()
		f.delCalls = append(f.delCalls, string(body))
		f.mu.Unlock()
		writeResponse(`<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2"/>`)

	case strings.Contains(action, "GetExternalIPAddress"):
		writeResponse(`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
<NewExternalIPAddress>203.0.113.1</NewExternalIPAddress>
</u:GetExternalIPAddressResponse>`)

	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func shortenSearchTimeout(t *testing.T) {
	t.Helper()
	old := searchTimeout
	searchTimeout = 250 * time.Millisecond
	t.Cleanup(func() {
		searchTimeout = old
	})
}

func TestDiscoverUnicast(t *testing.T) {
	shortenSearchTimeout(t)
	igd := startFakeIGD(t, func(st string) bool {
		return st == "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
	}, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gateway, err := discover(ctx, igd.addr())
	require.NoError(t, err)
	assert.Equal(t, "UPnP unicast (IP2)", gateway.Type())

	deviceAddr, err := gateway.GetDeviceAddress()
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", deviceAddr.String())

	externalIP, err := gateway.GetExternalAddress()
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.1", externalIP.String())

	externalPort, err := gateway.AddPortMapping(ctx, "udp", 51820, "NetBird", 2*time.Hour)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, externalPort, 10000)

	igd.mu.Lock()
	require.Len(t, igd.addCalls, 1)
	mappingBody := igd.addCalls[0].body
	igd.mu.Unlock()
	assert.Contains(t, mappingBody, "<NewInternalPort>51820</NewInternalPort>")
	assert.Contains(t, mappingBody, "<NewInternalClient>127.0.0.1</NewInternalClient>")
	assert.Contains(t, mappingBody, "<NewProtocol>UDP</NewProtocol>")
	assert.Contains(t, mappingBody, "<NewLeaseDuration>7200</NewLeaseDuration>")

	// Renewal reuses the previously mapped external port.
	renewedPort, err := gateway.AddPortMapping(ctx, "udp", 51820, "NetBird", 2*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, externalPort, renewedPort)

	require.NoError(t, gateway.DeletePortMapping(ctx, "udp", 51820))
	igd.mu.Lock()
	require.Len(t, igd.delCalls, 1)
	deleteBody := igd.delCalls[0]
	igd.mu.Unlock()
	assert.Contains(t, deleteBody, fmt.Sprintf("<NewExternalPort>%d</NewExternalPort>", externalPort))
}

func TestDiscoverSSDPAllFallback(t *testing.T) {
	shortenSearchTimeout(t)
	igd := startFakeIGD(t, func(st string) bool {
		return st == "ssdp:all"
	}, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gateway, err := discover(ctx, igd.addr())
	require.NoError(t, err)
	assert.Equal(t, "UPnP unicast (IP2)", gateway.Type())
}

func TestDiscoverNoGateway(t *testing.T) {
	shortenSearchTimeout(t)
	// A socket that never answers.
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = udpConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = discover(ctx, udpConn.LocalAddr().String())
	require.Error(t, err)
}

func TestPermanentLeaseFaultSurfacesErrorCode(t *testing.T) {
	shortenSearchTimeout(t)
	igd := startFakeIGD(t, func(st string) bool {
		return st == "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
	}, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gateway, err := discover(ctx, igd.addr())
	require.NoError(t, err)

	// The manager detects permanent-lease-only gateways by matching
	// <errorCode>725</errorCode> in the error text and retries with TTL 0.
	_, err = gateway.AddPortMapping(ctx, "udp", 51820, "NetBird", 2*time.Hour)
	require.Error(t, err)
	assert.Regexp(t, `<errorCode>\s*725\s*</errorCode>`, err.Error())

	externalPort, err := gateway.AddPortMapping(ctx, "udp", 51820, "NetBird", 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, externalPort, 10000)
}
