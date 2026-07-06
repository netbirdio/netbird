// Package upnp implements UPnP IGD gateway discovery over unicast SSDP.
//
// The multicast SSDP discovery performed by libp2p/go-nat is not delivered on
// networks that filter multicast (hypervisor bridges, IGMP-snooping switches,
// some Wi-Fi access points). Gateways based on MiniUPnPd (OPNsense, pfSense,
// OpenWrt) answer unicast M-SEARCH requests sent directly to them (UPnP Device
// Architecture 1.1, section 1.3.2), so searching the default gateway directly
// works where multicast discovery cannot.
package upnp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/httpu"
	"github.com/libp2p/go-nat"
	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
)

const (
	ssdpPort = "1900"
	// searchRepeats is how many times each M-SEARCH datagram is sent, since
	// SSDP runs over UDP and datagrams may be dropped.
	searchRepeats = 3
)

// searchTimeout is how long each search waits for responses. Variable so
// tests can shorten it.
var searchTimeout = 2 * time.Second

// searchTargets are tried in order until one yields a usable gateway.
var searchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"ssdp:all",
}

// serviceRank orders WAN connection services by preference, matching go-nat.
var serviceRank = map[string]int{
	internetgateway2.URN_WANIPConnection_2:  3,
	internetgateway2.URN_WANIPConnection_1:  2,
	internetgateway2.URN_WANPPPConnection_1: 1,
}

// Discover attempts to find a UPnP IGD by sending unicast SSDP searches to
// the default gateway.
func Discover(ctx context.Context) (nat.NAT, error) {
	gateway, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("get default gateway: %w", err)
	}
	return discover(ctx, net.JoinHostPort(gateway.String(), ssdpPort))
}

func discover(ctx context.Context, gatewayAddr string) (nat.NAT, error) {
	client, err := httpu.NewHTTPUClient()
	if err != nil {
		return nil, fmt.Errorf("create SSDP client: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Debugf("close SSDP client: %v", err)
		}
	}()

	checked := make(map[string]bool)
	for _, target := range searchTargets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		locations, err := search(client, gatewayAddr, target)
		if err != nil {
			log.Debugf("unicast SSDP search for %s at %s: %v", target, gatewayAddr, err)
			continue
		}

		for _, location := range locations {
			if checked[location] {
				continue
			}
			checked[location] = true

			gateway, err := natFromLocation(ctx, location)
			if err != nil {
				log.Debugf("UPnP device at %s: %v", location, err)
				continue
			}
			return gateway, nil
		}
	}

	return nil, fmt.Errorf("no UPnP gateway found at %s", gatewayAddr)
}

// search sends a unicast M-SEARCH to gatewayAddr and returns the description
// URLs of the devices that answered.
func search(client *httpu.HTTPUClient, gatewayAddr, searchTarget string) ([]string, error) {
	mx := max(int(searchTimeout/time.Second), 1)
	req := &http.Request{
		Method: "M-SEARCH",
		// httpu sends the request to req.Host, making the search unicast.
		Host: gatewayAddr,
		URL:  &url.URL{Opaque: "*"},
		// Header keys are set verbatim (map literal keys bypass Go's
		// canonicalization) to keep the upper-case field names SSDP
		// implementations expect.
		Header: http.Header{
			"HOST": []string{gatewayAddr},
			"MAN":  []string{`"ssdp:discover"`},
			"MX":   []string{strconv.Itoa(mx)},
			"ST":   []string{searchTarget},
		},
	}

	responses, err := client.Do(req, searchTimeout, searchRepeats) //nolint:bodyclose // httpu.Do returns a slice; bodies are closed in the loop below.
	if err != nil {
		return nil, err
	}

	var locations []string
	for _, resp := range responses {
		if resp.Body != nil {
			if err := resp.Body.Close(); err != nil {
				log.Debugf("close SSDP response body: %v", err)
			}
		}
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if location := resp.Header.Get("Location"); location != "" {
			locations = append(locations, location)
		}
	}
	return locations, nil
}

// natFromLocation fetches the device description and returns a NAT backed by
// the most preferred WAN connection service it offers.
func natFromLocation(ctx context.Context, location string) (nat.NAT, error) {
	loc, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse location: %w", err)
	}

	root, err := goupnp.DeviceByURLCtx(ctx, loc)
	if err != nil {
		return nil, fmt.Errorf("fetch device description: %w", err)
	}

	var services []*goupnp.Service
	root.Device.VisitServices(func(srv *goupnp.Service) {
		if serviceRank[srv.ServiceType] > 0 {
			services = append(services, srv)
		}
	})
	sort.SliceStable(services, func(i, j int) bool {
		return serviceRank[services[i].ServiceType] > serviceRank[services[j].ServiceType]
	})

	for _, srv := range services {
		gateway, err := natFromService(ctx, root, loc, srv)
		if err != nil {
			log.Debugf("UPnP service %s at %s: %v", srv.ServiceType, location, err)
			continue
		}
		return gateway, nil
	}

	return nil, fmt.Errorf("no usable WAN connection service in device at %s", location)
}

func natFromService(ctx context.Context, root *goupnp.RootDevice, loc *url.URL, srv *goupnp.Service) (nat.NAT, error) {
	serviceClient := goupnp.ServiceClient{
		SOAPClient: srv.NewSOAPClient(),
		RootDevice: root,
		Location:   loc,
		Service:    srv,
	}

	var client igdClient
	var natType string
	switch srv.ServiceType {
	case internetgateway2.URN_WANIPConnection_2:
		client = &internetgateway2.WANIPConnection2{ServiceClient: serviceClient}
		natType = "UPnP unicast (IP2)"
	case internetgateway2.URN_WANIPConnection_1:
		client = &internetgateway2.WANIPConnection1{ServiceClient: serviceClient}
		natType = "UPnP unicast (IP1)"
	case internetgateway2.URN_WANPPPConnection_1:
		client = &internetgateway2.WANPPPConnection1{ServiceClient: serviceClient}
		natType = "UPnP unicast (PPP1)"
	default:
		return nil, fmt.Errorf("unsupported service type %s", srv.ServiceType)
	}

	_, isNAT, err := client.GetNATRSIPStatusCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("get NAT status: %w", err)
	}
	if !isNAT {
		return nil, errors.New("gateway reports NAT disabled")
	}

	return &NAT{
		client:  client,
		natType: natType,
		root:    root,
		ports:   make(map[int]int),
	}, nil
}

// getDefaultGateway returns the default IPv4 gateway using the system routing table.
func getDefaultGateway() (net.IP, error) {
	router, err := netroute.New()
	if err != nil {
		return nil, err
	}

	dst := net.IPv4zero
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		// go-netroute v0.4.0 rejects unspecified destinations client-side on Linux/Android.
		dst = net.IPv4(0, 0, 0, 1)
	}
	_, gateway, _, err := router.Route(dst)
	if err != nil {
		return nil, err
	}

	if gateway == nil {
		return nil, nat.ErrNoNATFound
	}

	return gateway, nil
}
