package nat

import (
	"errors"
	"github.com/pion/stun"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

// Most of the code of this file is taken from the https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour package
// Copyright 2018 Pion LLC

const (
	messageHeaderSize = 20
)

//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
var (
	errResponseMessage = errors.New("error reading from response message channel")
	errTimedOut        = errors.New("timed out waiting for response")
	errNoOtherAddress  = errors.New("no OTHER-ADDRESS in the STUN response message")
)

type Discovery struct {
	stunAddr string
	// a STUN server connection timeout
	timeout time.Duration
}

func NewDiscovery(stunAddr string, timeout time.Duration) *Discovery {
	return &Discovery{
		stunAddr: stunAddr,
		timeout:  timeout,
	}
}

type Candidate struct {
	Ip   net.IP
	Port int
	// a type of the candidate [host, srflx, prflx, relay] - see WebRTC spec
	Type string
}

type Behaviour struct {
	// indicates whether NAT is hard - address dependent or  address and port dependent
	IsStrict bool
	// a list of external addresses (IP:port) received from the STUN server while testing NAT
	// these can be used for the Wireguard connection in case IsStrict = false
	Candidates []*Candidate

	LocalPort int
}

//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
type stunServerConn struct {
	conn        net.PacketConn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

func (c *stunServerConn) Close() error {
	return c.conn.Close()
}

// Discovers connection candidates and NAT behaviour by probing STUN server.
// For proper NAT behaviour it is required for the The STUN server to have multiple IPs (for probing different destinations).
// See https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour and https://tools.ietf.org/html/rfc5780 for details.
// In case the returned Behaviour.IsStrict = false the Behaviour.LocalPort and any of the Probes can be used for the Wireguard communication
// since the hole has been already punched.
// When Behaviour.IsStrict = true the hole punching requires extra actions.
func (d *Discovery) Discover() (*Behaviour, error) {

	// get a local address (candidate)
	localConn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Errorf("Error getting local address: %s\n", err.Error())
		return nil, err
	}
	log.Infof("Local address %s", localConn.LocalAddr().String())
	err = localConn.Close()
	if err != nil {
		return nil, err
	}

	lAddr, err := net.ResolveUDPAddr("udp4", localConn.LocalAddr().String())

	mapTestConn, err := connect(d.stunAddr, lAddr)
	if err != nil {
		log.Errorf("Error creating STUN connection: %s\n", err.Error())
		return nil, err
	}

	defer mapTestConn.Close()

	var candidates = []*Candidate{{Ip: lAddr.IP, Port: lAddr.Port, Type: "host"}}

	// Test I: Regular binding request
	log.Info("Mapping Test I: Regular binding request")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr, d.timeout)
	if err != nil {
		return nil, err
	}

	// Parse response message for XOR-MAPPED-ADDRESS and make sure OTHER-ADDRESS valid
	resps1 := parse(resp)
	if resps1.xorAddr == nil || resps1.otherAddr == nil {
		log.Warn("Error: NAT discovery feature not supported by this STUN server")
		return nil, errNoOtherAddress
	}
	addr, err := net.ResolveUDPAddr("udp4", resps1.otherAddr.String())
	if err != nil {
		log.Errorf("Failed resolving OTHER-ADDRESS: %v\n", resps1.otherAddr)
		return nil, err
	}
	mapTestConn.OtherAddr = addr
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", resps1.xorAddr)

	candidates = append(candidates, &Candidate{resps1.xorAddr.IP, resps1.xorAddr.Port, "srflx"})

	// Assert mapping behavior
	if resps1.xorAddr.String() == mapTestConn.LocalAddr.String() {
		log.Info("=> NAT mapping behavior: endpoint independent (no NAT)")
		return &Behaviour{
			IsStrict:   false,
			Candidates: candidates,
			LocalPort:  mapTestConn.LocalAddr.(*net.UDPAddr).Port,
		}, nil
	}

	// Test II: Send binding request to the other address but primary port
	log.Info("Mapping Test II: Send binding request to the other address but primary port")
	oaddr := *mapTestConn.OtherAddr
	oaddr.Port = mapTestConn.RemoteAddr.Port
	resp, err = mapTestConn.roundTrip(request, &oaddr, d.timeout)
	if err != nil {
		return nil, err
	}

	resps2 := parse(resp)
	candidates = append(candidates, &Candidate{resps2.xorAddr.IP, resps2.xorAddr.Port, "srflx"})
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", resps2.xorAddr)

	// Assert mapping behavior
	if resps2.xorAddr.String() == resps1.xorAddr.String() {
		log.Info("=> NAT mapping behavior: endpoint independent")
		return &Behaviour{
			IsStrict:   false,
			Candidates: candidates,
			LocalPort:  mapTestConn.LocalAddr.(*net.UDPAddr).Port,
		}, nil
	}

	// Test III: Send binding request to the other address and port
	log.Info("Mapping Test III: Send binding request to the other address and port")
	resp, err = mapTestConn.roundTrip(request, mapTestConn.OtherAddr, d.timeout)
	if err != nil {
		return nil, err
	}

	resps3 := parse(resp)
	candidates = append(candidates, &Candidate{resps3.xorAddr.IP, resps3.xorAddr.Port, "srflx"})
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", resps3.xorAddr)

	// Assert mapping behavior
	if resps3.xorAddr.String() == resps2.xorAddr.String() {
		log.Info("=> NAT mapping behavior: address dependent")
	} else {
		log.Info("=> NAT mapping behavior: address and port dependent")
	}

	return &Behaviour{
		IsStrict:   true,
		Candidates: candidates,
		LocalPort:  mapTestConn.LocalAddr.(*net.UDPAddr).Port,
	}, nil
}

//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
func connect(stunAddr string, lAddr *net.UDPAddr) (*stunServerConn, error) {
	log.Debugf("connecting to STUN server: %s\n", stunAddr)
	addr, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		log.Errorf("Error resolving address: %s\n", err.Error())
		return nil, err
	}

	c, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return nil, err
	}
	log.Debugf("Local address: %s\n", c.LocalAddr())
	log.Debugf("Remote address: %s\n", addr.String())

	mChan := listen(c)

	return &stunServerConn{
		conn:        c,
		LocalAddr:   c.LocalAddr(),
		RemoteAddr:  addr,
		messageChan: mChan,
	}, nil
}

//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
func listen(conn *net.UDPConn) (messages chan *stun.Message) {
	messages = make(chan *stun.Message)
	go func() {
		for {
			buf := make([]byte, 1024)

			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			log.Debugf("Response from %v: (%v bytes)\n", addr, n)
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				log.Debugf("Error decoding message: %v\n", err)
				close(messages)
				return
			}

			messages <- m
		}
	}()
	return
}

// Send request and wait for response or timeout
//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
func (c *stunServerConn) roundTrip(msg *stun.Message, addr net.Addr, timeout time.Duration) (*stun.Message, error) {
	_ = msg.NewTransactionID()
	log.Debugf("Sending to %v: (%v bytes)\n", addr, msg.Length+messageHeaderSize)
	log.Debugf("%v\n", msg)
	for _, attr := range msg.Attributes {
		log.Debugf("\t%v (l=%v)\n", attr, attr.Length)
	}
	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		log.Errorf("Error sending request to %v\n", addr)
		return nil, err
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, errResponseMessage
		}
		return m, nil
		//todo configure timeout
	case <-time.After(timeout):
		log.Warnf("Timed out waiting for response from server %v\n", addr)
		return nil, errTimedOut
	}
}

// Parse a STUN message
//taken from https://github.com/pion/stun/tree/master/cmd/stun-nat-behaviour
func parse(msg *stun.Message) (ret struct {
	xorAddr   *stun.XORMappedAddress
	otherAddr *stun.OtherAddress
	//respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
}) {
	ret.mappedAddr = &stun.MappedAddress{}
	ret.xorAddr = &stun.XORMappedAddress{}
	//ret.respOrigin = &stun.ResponseOrigin{}
	ret.otherAddr = &stun.OtherAddress{}
	ret.software = &stun.Software{}
	if ret.xorAddr.GetFrom(msg) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(msg) != nil {
		ret.otherAddr = nil
	}
	/*if ret.respOrigin.GetFrom(msg) != nil {
		ret.respOrigin = nil
	}*/
	if ret.mappedAddr.GetFrom(msg) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(msg) != nil {
		ret.software = nil
	}
	log.Debugf("%v\n", msg)
	log.Debugf("\tMAPPED-ADDRESS:     %v\n", ret.mappedAddr)
	log.Debugf("\tXOR-MAPPED-ADDRESS: %v\n", ret.xorAddr)
	//log.Debugf("\tRESPONSE-ORIGIN:    %v\n", ret.respOrigin)
	log.Debugf("\tOTHER-ADDRESS:      %v\n", ret.otherAddr)
	log.Debugf("\tSOFTWARE: %v\n", ret.software)
	for _, attr := range msg.Attributes {
		switch attr.Type {
		case
			stun.AttrXORMappedAddress,
			stun.AttrOtherAddress,
			//stun.AttrResponseOrigin,
			stun.AttrMappedAddress,
			stun.AttrSoftware:
			break //nolint: staticcheck
		default:
			log.Debugf("\t%v (l=%v)\n", attr, attr.Length)
		}
	}
	return ret
}
