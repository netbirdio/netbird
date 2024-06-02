package internal

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/acl"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/relay"
	"github.com/netbirdio/netbird/client/internal/rosenpass"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/wgproxy"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/iface/bind"
	mgm "github.com/netbirdio/netbird/management/client"
	mgmProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/route"
	signal "github.com/netbirdio/netbird/signal/client"
	sProto "github.com/netbirdio/netbird/signal/proto"
	"github.com/netbirdio/netbird/util"
)

// PeerConnectionTimeoutMax is a timeout of an initial connection attempt to a remote peer.
// E.g. this peer will wait PeerConnectionTimeoutMax for the remote peer to respond,
// if not successful then it will retry the connection attempt.
// Todo pass timeout at EnginConfig
const (
	PeerConnectionTimeoutMax = 45000 // ms
	PeerConnectionTimeoutMin = 30000 // ms
)

var ErrResetConnection = fmt.Errorf("reset connection")

// EngineConfig is a config for the Engine
type EngineConfig struct {
	WgPort      int
	WgIfaceName string

	// WgAddr is a Wireguard local address (Netbird Network IP)
	WgAddr  string
	WgAddr6 string

	// WgPrivateKey is a Wireguard private key of our peer (it MUST never leave the machine)
	WgPrivateKey wgtypes.Key

	// NetworkMonitor is a flag to enable network monitoring
	NetworkMonitor bool

	// IFaceBlackList is a list of network interfaces to ignore when discovering connection candidates (ICE related)
	IFaceBlackList       []string
	DisableIPv6Discovery bool

	PreSharedKey *wgtypes.Key

	// UDPMuxPort default value 0 - the system will pick an available port
	UDPMuxPort int

	// UDPMuxSrflxPort default value 0 - the system will pick an available port
	UDPMuxSrflxPort int

	// SSHKey is a private SSH key in a PEM format
	SSHKey []byte

	NATExternalIPs []string

	CustomDNSAddress string

	RosenpassEnabled    bool
	RosenpassPermissive bool

	ServerSSHAllowed bool
}

// Engine is a mechanism responsible for reacting on Signal and Management stream events and managing connections to the remote peers.
type Engine struct {
	// signal is a Signal Service client
	signal signal.Client
	// mgmClient is a Management Service client
	mgmClient mgm.Client
	// peerConns is a map that holds all the peers that are known to this peer
	peerConns map[string]*peer.Conn

	beforePeerHook peer.BeforeAddPeerHookFunc
	afterPeerHook  peer.AfterRemovePeerHookFunc

	// rpManager is a Rosenpass manager
	rpManager *rosenpass.Manager

	// syncMsgMux is used to guarantee sequential Management Service message processing
	syncMsgMux *sync.Mutex

	config    *EngineConfig
	mobileDep MobileDependency

	// STUNs is a list of STUN servers used by ICE
	STUNs []*stun.URI
	// TURNs is a list of STUN servers used by ICE
	TURNs []*stun.URI

	// clientRoutes is the most recent list of clientRoutes received from the Management Service
	clientRoutes route.HAMap

	clientCtx    context.Context
	clientCancel context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc

	wgInterface    *iface.WGIface
	wgProxyFactory *wgproxy.Factory

	udpMux *bind.UniversalUDPMuxDefault

	// networkSerial is the latest CurrentSerial (state ID) of the network sent by the Management service
	networkSerial uint64

	networkMonitor *networkmonitor.NetworkMonitor

	sshServerFunc func(hostKeyPEM []byte, addr string) (nbssh.Server, error)
	sshServer     nbssh.Server

	statusRecorder *peer.Status

	firewall     manager.Manager
	routeManager routemanager.Manager
	acl          acl.Manager

	dnsServer dns.Server

	mgmProbe    *Probe
	signalProbe *Probe
	relayProbe  *Probe
	wgProbe     *Probe

	wgConnWorker sync.WaitGroup
}

// Peer is an instance of the Connection Peer
type Peer struct {
	WgPubKey     string
	WgAllowedIps string
}

// NewEngine creates a new Connection Engine
func NewEngine(
	clientCtx context.Context,
	clientCancel context.CancelFunc,
	signalClient signal.Client,
	mgmClient mgm.Client,
	config *EngineConfig,
	mobileDep MobileDependency,
	statusRecorder *peer.Status,
) *Engine {
	return NewEngineWithProbes(
		clientCtx,
		clientCancel,
		signalClient,
		mgmClient,
		config,
		mobileDep,
		statusRecorder,
		nil,
		nil,
		nil,
		nil,
	)
}

// NewEngineWithProbes creates a new Connection Engine with probes attached
func NewEngineWithProbes(
	clientCtx context.Context,
	clientCancel context.CancelFunc,
	signalClient signal.Client,
	mgmClient mgm.Client,
	config *EngineConfig,
	mobileDep MobileDependency,
	statusRecorder *peer.Status,
	mgmProbe *Probe,
	signalProbe *Probe,
	relayProbe *Probe,
	wgProbe *Probe,
) *Engine {

	return &Engine{
		clientCtx:      clientCtx,
		clientCancel:   clientCancel,
		signal:         signalClient,
		mgmClient:      mgmClient,
		peerConns:      make(map[string]*peer.Conn),
		syncMsgMux:     &sync.Mutex{},
		config:         config,
		mobileDep:      mobileDep,
		STUNs:          []*stun.URI{},
		TURNs:          []*stun.URI{},
		networkSerial:  0,
		sshServerFunc:  nbssh.DefaultSSHServer,
		statusRecorder: statusRecorder,
		mgmProbe:       mgmProbe,
		signalProbe:    signalProbe,
		relayProbe:     relayProbe,
		wgProbe:        wgProbe,
	}
}

func (e *Engine) Stop() error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if e.cancel != nil {
		e.cancel()
	}

	// stopping network monitor first to avoid starting the engine again
	if e.networkMonitor != nil {
		e.networkMonitor.Stop()
	}
	log.Info("Network monitor: stopped")

	err := e.removeAllPeers()
	if err != nil {
		return err
	}

	e.clientRoutes = nil

	// very ugly but we want to remove peers from the WireGuard interface first before removing interface.
	// Removing peers happens in the conn.Close() asynchronously
	time.Sleep(500 * time.Millisecond)

	e.close()
	e.wgConnWorker.Wait()
	log.Infof("stopped Netbird Engine")
	return nil
}

// Start creates a new WireGuard tunnel interface and listens to events from Signal and Management services
// Connections to remote peers are not established here.
// However, they will be established once an event with a list of peers to connect to will be received from Management Service
func (e *Engine) Start() error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if e.cancel != nil {
		e.cancel()
	}
	e.ctx, e.cancel = context.WithCancel(e.clientCtx)

	e.wgProxyFactory = wgproxy.NewFactory(e.ctx, e.config.WgPort)

	wgIface, err := e.newWgIface()
	if err != nil {
		log.Errorf("failed creating wireguard interface instance %s: [%s]", e.config.WgIfaceName, err)
		return fmt.Errorf("new wg interface: %w", err)
	}
	e.wgInterface = wgIface

	if e.config.RosenpassEnabled {
		log.Infof("rosenpass is enabled")
		if e.config.RosenpassPermissive {
			log.Infof("running rosenpass in permissive mode")
		} else {
			log.Infof("running rosenpass in strict mode")
		}
		e.rpManager, err = rosenpass.NewManager(e.config.PreSharedKey, e.config.WgIfaceName)
		if err != nil {
			return fmt.Errorf("create rosenpass manager: %w", err)
		}
		err := e.rpManager.Run()
		if err != nil {
			return fmt.Errorf("run rosenpass manager: %w", err)
		}
	}

	initialRoutes, dnsServer, err := e.newDnsServer()
	if err != nil {
		e.close()
		return fmt.Errorf("create dns server: %w", err)
	}
	e.dnsServer = dnsServer

	e.routeManager = routemanager.NewManager(e.ctx, e.config.WgPrivateKey.PublicKey().String(), e.wgInterface, e.statusRecorder, initialRoutes)
	beforePeerHook, afterPeerHook, err := e.routeManager.Init()
	if err != nil {
		log.Errorf("Failed to initialize route manager: %s", err)
	} else {
		e.beforePeerHook = beforePeerHook
		e.afterPeerHook = afterPeerHook
	}

	e.routeManager.SetRouteChangeListener(e.mobileDep.NetworkChangeListener)

	err = e.wgInterfaceCreate()
	if err != nil {
		log.Errorf("failed creating tunnel interface %s: [%s]", e.config.WgIfaceName, err.Error())
		e.close()
		return fmt.Errorf("create wg interface: %w", err)
	}

	e.firewall, err = firewall.NewFirewall(e.ctx, e.wgInterface)
	if err != nil {
		log.Errorf("failed creating firewall manager: %s", err)
	}

	if e.firewall != nil && e.firewall.IsServerRouteSupported() {
		err = e.routeManager.EnableServerRouter(e.firewall)
		if err != nil {
			e.close()
			return fmt.Errorf("enable server router: %w", err)
		}
	}

	e.udpMux, err = e.wgInterface.Up()
	if err != nil {
		log.Errorf("failed to pull up wgInterface [%s]: %s", e.wgInterface.Name(), err.Error())
		e.close()
		return fmt.Errorf("up wg interface: %w", err)
	}

	if e.firewall != nil {
		e.acl = acl.NewDefaultManager(e.firewall)
	}

	err = e.dnsServer.Initialize()
	if err != nil {
		e.close()
		return fmt.Errorf("initialize dns server: %w", err)
	}

	e.receiveSignalEvents()
	e.receiveManagementEvents()
	e.receiveProbeEvents()

	// starting network monitor at the very last to avoid disruptions
	e.startNetworkMonitor()

	return nil
}

// modifyPeers updates peers that have been modified (e.g. IP address has been changed).
// It closes the existing connection, removes it from the peerConns map, and creates a new one.
func (e *Engine) modifyPeers(peersUpdate []*mgmProto.RemotePeerConfig) error {

	// first, check if peers have been modified
	var modified []*mgmProto.RemotePeerConfig
	for _, p := range peersUpdate {
		peerPubKey := p.GetWgPubKey()
		if peerConn, ok := e.peerConns[peerPubKey]; ok {
			if peerConn.WgConfig().AllowedIps != strings.Join(p.AllowedIps, ",") {
				modified = append(modified, p)
				continue
			}
			err := e.statusRecorder.UpdatePeerFQDN(peerPubKey, p.GetFqdn())
			if err != nil {
				log.Warnf("error updating peer's %s fqdn in the status recorder, got error: %v", peerPubKey, err)
			}
		}
	}

	// second, close all modified connections and remove them from the state map
	for _, p := range modified {
		err := e.removePeer(p.GetWgPubKey())
		if err != nil {
			return err
		}
	}
	// third, add the peer connections again
	for _, p := range modified {
		err := e.addNewPeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

// removePeers finds and removes peers that do not exist anymore in the network map received from the Management Service.
// It also removes peers that have been modified (e.g. change of IP address). They will be added again in addPeers method.
func (e *Engine) removePeers(peersUpdate []*mgmProto.RemotePeerConfig) error {
	currentPeers := make([]string, 0, len(e.peerConns))
	for p := range e.peerConns {
		currentPeers = append(currentPeers, p)
	}

	newPeers := make([]string, 0, len(peersUpdate))
	for _, p := range peersUpdate {
		newPeers = append(newPeers, p.GetWgPubKey())
	}

	toRemove := util.SliceDiff(currentPeers, newPeers)

	for _, p := range toRemove {
		err := e.removePeer(p)
		if err != nil {
			return err
		}
		log.Infof("removed peer %s", p)
	}
	return nil
}

func (e *Engine) removeAllPeers() error {
	log.Debugf("removing all peer connections")
	for p := range e.peerConns {
		err := e.removePeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

// removePeer closes an existing peer connection, removes a peer, and clears authorized key of the SSH server
func (e *Engine) removePeer(peerKey string) error {
	log.Debugf("removing peer from engine %s", peerKey)

	if !isNil(e.sshServer) {
		e.sshServer.RemoveAuthorizedKey(peerKey)
	}

	defer func() {
		err := e.statusRecorder.RemovePeer(peerKey)
		if err != nil {
			log.Warnf("received error when removing peer %s from status recorder: %v", peerKey, err)
		}
	}()

	conn, exists := e.peerConns[peerKey]
	if exists {
		delete(e.peerConns, peerKey)
		err := conn.Close()
		if err != nil {
			switch err.(type) {
			case *peer.ConnectionAlreadyClosedError:
				return nil
			default:
				return err
			}
		}
	}
	return nil
}

func signalCandidate(candidate ice.Candidate, myKey wgtypes.Key, remoteKey wgtypes.Key, s signal.Client) error {
	err := s.Send(&sProto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &sProto.Body{
			Type:    sProto.Body_CANDIDATE,
			Payload: candidate.Marshal(),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func sendSignal(message *sProto.Message, s signal.Client) error {
	return s.Send(message)
}

// SignalOfferAnswer signals either an offer or an answer to remote peer
func SignalOfferAnswer(offerAnswer peer.OfferAnswer, myKey wgtypes.Key, remoteKey wgtypes.Key, s signal.Client,
	isAnswer bool) error {
	var t sProto.Body_Type
	if isAnswer {
		t = sProto.Body_ANSWER
	} else {
		t = sProto.Body_OFFER
	}

	msg, err := signal.MarshalCredential(myKey, offerAnswer.WgListenPort, remoteKey, &signal.Credential{
		UFrag: offerAnswer.IceCredentials.UFrag,
		Pwd:   offerAnswer.IceCredentials.Pwd,
	}, t, offerAnswer.RosenpassPubKey, offerAnswer.RosenpassAddr)
	if err != nil {
		return err
	}

	err = s.Send(msg)
	if err != nil {
		return err
	}

	return nil
}

func (e *Engine) handleSync(update *mgmProto.SyncResponse) error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if update.GetWiretrusteeConfig() != nil {
		err := e.updateTURNs(update.GetWiretrusteeConfig().GetTurns())
		if err != nil {
			return err
		}

		err = e.updateSTUNs(update.GetWiretrusteeConfig().GetStuns())
		if err != nil {
			return err
		}

		// todo update signal
	}

	if update.GetNetworkMap() != nil {
		// only apply new changes and ignore old ones
		err := e.updateNetworkMap(update.GetNetworkMap())
		if err != nil {
			return err
		}
	}

	return nil
}

func isNil(server nbssh.Server) bool {
	return server == nil || reflect.ValueOf(server).IsNil()
}

func (e *Engine) updateSSH(sshConf *mgmProto.SSHConfig) error {

	if !e.config.ServerSSHAllowed {
		log.Warnf("running SSH server is not permitted")
		return nil
	} else {

		if sshConf.GetSshEnabled() {
			if runtime.GOOS == "windows" {
				log.Warnf("running SSH server on Windows is not supported")
				return nil
			}
			// start SSH server if it wasn't running
			if isNil(e.sshServer) {
				// nil sshServer means it has not yet been started
				var err error
				e.sshServer, err = e.sshServerFunc(e.config.SSHKey,
					fmt.Sprintf("%s:%d", e.wgInterface.Address().IP.String(), nbssh.DefaultSSHPort))
				if err != nil {
					return err
				}
				go func() {
					// blocking
					err = e.sshServer.Start()
					if err != nil {
						// will throw error when we stop it even if it is a graceful stop
						log.Debugf("stopped SSH server with error %v", err)
					}
					e.syncMsgMux.Lock()
					defer e.syncMsgMux.Unlock()
					e.sshServer = nil
					log.Infof("stopped SSH server")
				}()
			} else {
				log.Debugf("SSH server is already running")
			}
		} else if !isNil(e.sshServer) {
			// Disable SSH server request, so stop it if it was running
			err := e.sshServer.Stop()
			if err != nil {
				log.Warnf("failed to stop SSH server %v", err)
			}
			e.sshServer = nil
		}
		return nil

	}
}

func (e *Engine) updateConfig(conf *mgmProto.PeerConfig) error {
	if e.wgInterface.Address().String() != conf.Address {
		oldAddr := e.wgInterface.Address().String()
		log.Debugf("updating peer address from %s to %s", oldAddr, conf.Address)
		err := e.wgInterface.UpdateAddr(conf.Address)
		if err != nil {
			return err
		}
		e.config.WgAddr = conf.Address
		log.Infof("updated peer address from %s to %s", oldAddr, conf.Address)
	}

	if e.wgInterface.Address6() == nil && conf.Address6 != "" ||
		e.wgInterface.Address6() != nil && e.wgInterface.Address6().String() != conf.Address6 {
		oldAddr := "none"
		if e.wgInterface.Address6() != nil {
			oldAddr = e.wgInterface.Address6().String()
		}
		newAddr := "none"
		if conf.Address6 != "" {
			newAddr = conf.Address6
		}
		log.Debugf("updating peer IPv6 address from %s to %s", oldAddr, newAddr)
		err := e.wgInterface.UpdateAddr6(conf.Address6)
		if err != nil {
			return err
		}
		e.config.WgAddr6 = conf.Address6

		err = e.acl.ResetV6Acl()
		if err != nil {
			return err
		}

		e.routeManager.ResetV6Routes()
		log.Infof("updated peer IPv6 address from %s to %s", oldAddr, conf.Address6)
	}

	if conf.GetSshConfig() != nil {
		err := e.updateSSH(conf.GetSshConfig())
		if err != nil {
			log.Warnf("failed handling SSH server setup %v", err)
		}
	}

	e.statusRecorder.UpdateLocalPeerState(peer.LocalPeerState{
		IP:              e.config.WgAddr,
		IP6:             e.config.WgAddr6,
		PubKey:          e.config.WgPrivateKey.PublicKey().String(),
		KernelInterface: iface.WireGuardModuleIsLoaded(),
		FQDN:            conf.GetFqdn(),
	})

	return nil
}

// receiveManagementEvents connects to the Management Service event stream to receive updates from the management service
// E.g. when a new peer has been registered and we are allowed to connect to it.
func (e *Engine) receiveManagementEvents() {
	go func() {
		err := e.mgmClient.Sync(e.ctx, e.handleSync)
		if err != nil {
			// happens if management is unavailable for a long time.
			// We want to cancel the operation of the whole client
			_ = CtxGetState(e.ctx).Wrap(ErrResetConnection)
			e.clientCancel()
			return
		}
		log.Debugf("stopped receiving updates from Management Service")
	}()
	log.Debugf("connecting to Management Service updates stream")
}

func (e *Engine) updateSTUNs(stuns []*mgmProto.HostConfig) error {
	if len(stuns) == 0 {
		return nil
	}
	var newSTUNs []*stun.URI
	log.Debugf("got STUNs update from Management Service, updating")
	for _, s := range stuns {
		url, err := stun.ParseURI(s.Uri)
		if err != nil {
			return err
		}
		newSTUNs = append(newSTUNs, url)
	}
	e.STUNs = newSTUNs

	return nil
}

func (e *Engine) updateTURNs(turns []*mgmProto.ProtectedHostConfig) error {
	if len(turns) == 0 {
		return nil
	}
	var newTURNs []*stun.URI
	log.Debugf("got TURNs update from Management Service, updating")
	for _, turn := range turns {
		url, err := stun.ParseURI(turn.HostConfig.Uri)
		if err != nil {
			return err
		}
		url.Username = turn.User
		url.Password = turn.Password
		newTURNs = append(newTURNs, url)
	}
	e.TURNs = newTURNs

	return nil
}

func (e *Engine) updateNetworkMap(networkMap *mgmProto.NetworkMap) error {

	// intentionally leave it before checking serial because for now it can happen that peer IP changed but serial didn't
	if networkMap.GetPeerConfig() != nil {
		err := e.updateConfig(networkMap.GetPeerConfig())
		if err != nil {
			return err
		}
	}

	serial := networkMap.GetSerial()
	if e.networkSerial > serial {
		log.Debugf("received outdated NetworkMap with serial %d, ignoring", serial)
		return nil
	}

	log.Debugf("got peers update from Management Service, total peers to connect to = %d", len(networkMap.GetRemotePeers()))

	e.updateOfflinePeers(networkMap.GetOfflinePeers())

	// cleanup request, most likely our peer has been deleted
	if networkMap.GetRemotePeersIsEmpty() {
		err := e.removeAllPeers()
		e.statusRecorder.FinishPeerListModifications()
		if err != nil {
			return err
		}
	} else {
		err := e.removePeers(networkMap.GetRemotePeers())
		if err != nil {
			return err
		}

		err = e.modifyPeers(networkMap.GetRemotePeers())
		if err != nil {
			return err
		}

		err = e.addNewPeers(networkMap.GetRemotePeers())
		if err != nil {
			return err
		}

		e.statusRecorder.FinishPeerListModifications()

		// update SSHServer by adding remote peer SSH keys
		if !isNil(e.sshServer) {
			for _, config := range networkMap.GetRemotePeers() {
				if config.GetSshConfig() != nil && config.GetSshConfig().GetSshPubKey() != nil {
					err := e.sshServer.AddAuthorizedKey(config.WgPubKey, string(config.GetSshConfig().GetSshPubKey()))
					if err != nil {
						log.Warnf("failed adding authorized key to SSH DefaultServer %v", err)
					}
				}
			}
		}
	}
	protoRoutes := networkMap.GetRoutes()
	if protoRoutes == nil {
		protoRoutes = []*mgmProto.Route{}
	}

	_, clientRoutes, err := e.routeManager.UpdateRoutes(serial, toRoutes(protoRoutes))
	if err != nil {
		log.Errorf("failed to update clientRoutes, err: %v", err)
	}

	e.clientRoutes = clientRoutes

	protoDNSConfig := networkMap.GetDNSConfig()
	if protoDNSConfig == nil {
		protoDNSConfig = &mgmProto.DNSConfig{}
	}

	err = e.dnsServer.UpdateDNSServer(serial, toDNSConfig(protoDNSConfig))
	if err != nil {
		log.Errorf("failed to update dns server, err: %v", err)
	}

	if e.acl != nil {
		e.acl.ApplyFiltering(networkMap)
	}

	e.networkSerial = serial

	// Test received (upstream) servers for availability right away instead of upon usage.
	// If no server of a server group responds this will disable the respective handler and retry later.
	e.dnsServer.ProbeAvailability()

	return nil
}

func toRoutes(protoRoutes []*mgmProto.Route) []*route.Route {
	routes := make([]*route.Route, 0)
	for _, protoRoute := range protoRoutes {
		_, prefix, _ := route.ParseNetwork(protoRoute.Network)
		convertedRoute := &route.Route{
			ID:          route.ID(protoRoute.ID),
			Network:     prefix,
			NetID:       route.NetID(protoRoute.NetID),
			NetworkType: route.NetworkType(protoRoute.NetworkType),
			Peer:        protoRoute.Peer,
			Metric:      int(protoRoute.Metric),
			Masquerade:  protoRoute.Masquerade,
		}
		routes = append(routes, convertedRoute)
	}
	return routes
}

func toDNSConfig(protoDNSConfig *mgmProto.DNSConfig) nbdns.Config {
	dnsUpdate := nbdns.Config{
		ServiceEnable:    protoDNSConfig.GetServiceEnable(),
		CustomZones:      make([]nbdns.CustomZone, 0),
		NameServerGroups: make([]*nbdns.NameServerGroup, 0),
	}

	for _, zone := range protoDNSConfig.GetCustomZones() {
		dnsZone := nbdns.CustomZone{
			Domain: zone.GetDomain(),
		}
		for _, record := range zone.Records {
			dnsRecord := nbdns.SimpleRecord{
				Name:  record.GetName(),
				Type:  int(record.GetType()),
				Class: record.GetClass(),
				TTL:   int(record.GetTTL()),
				RData: record.GetRData(),
			}
			dnsZone.Records = append(dnsZone.Records, dnsRecord)
		}
		dnsUpdate.CustomZones = append(dnsUpdate.CustomZones, dnsZone)
	}

	for _, nsGroup := range protoDNSConfig.GetNameServerGroups() {
		dnsNSGroup := &nbdns.NameServerGroup{
			Primary:              nsGroup.GetPrimary(),
			Domains:              nsGroup.GetDomains(),
			SearchDomainsEnabled: nsGroup.GetSearchDomainsEnabled(),
		}
		for _, ns := range nsGroup.GetNameServers() {
			dnsNS := nbdns.NameServer{
				IP:     netip.MustParseAddr(ns.GetIP()),
				NSType: nbdns.NameServerType(ns.GetNSType()),
				Port:   int(ns.GetPort()),
			}
			dnsNSGroup.NameServers = append(dnsNSGroup.NameServers, dnsNS)
		}
		dnsUpdate.NameServerGroups = append(dnsUpdate.NameServerGroups, dnsNSGroup)
	}
	return dnsUpdate
}

func (e *Engine) updateOfflinePeers(offlinePeers []*mgmProto.RemotePeerConfig) {
	replacement := make([]peer.State, len(offlinePeers))
	for i, offlinePeer := range offlinePeers {
		log.Debugf("added offline peer %s", offlinePeer.Fqdn)
		replacement[i] = peer.State{
			IP:               strings.Join(offlinePeer.GetAllowedIps(), ","),
			PubKey:           offlinePeer.GetWgPubKey(),
			FQDN:             offlinePeer.GetFqdn(),
			ConnStatus:       peer.StatusDisconnected,
			ConnStatusUpdate: time.Now(),
			Mux:              new(sync.RWMutex),
		}
	}
	e.statusRecorder.ReplaceOfflinePeers(replacement)
}

// addNewPeers adds peers that were not know before but arrived from the Management service with the update
func (e *Engine) addNewPeers(peersUpdate []*mgmProto.RemotePeerConfig) error {
	for _, p := range peersUpdate {
		err := e.addNewPeer(p)
		if err != nil {
			return err
		}
	}
	return nil
}

// addNewPeer add peer if connection doesn't exist
func (e *Engine) addNewPeer(peerConfig *mgmProto.RemotePeerConfig) error {
	peerKey := peerConfig.GetWgPubKey()
	peerIPs := peerConfig.GetAllowedIps()
	if _, ok := e.peerConns[peerKey]; !ok {
		conn, err := e.createPeerConn(peerKey, strings.Join(peerIPs, ","))
		if err != nil {
			return fmt.Errorf("create peer connection: %w", err)
		}
		e.peerConns[peerKey] = conn

		if e.beforePeerHook != nil && e.afterPeerHook != nil {
			conn.AddBeforeAddPeerHook(e.beforePeerHook)
			conn.AddAfterRemovePeerHook(e.afterPeerHook)
		}

		err = e.statusRecorder.AddPeer(peerKey, peerConfig.Fqdn)
		if err != nil {
			log.Warnf("error adding peer %s to status recorder, got error: %v", peerKey, err)
		}

		e.wgConnWorker.Add(1)
		go e.connWorker(conn, peerKey)
	}
	return nil
}

func (e *Engine) connWorker(conn *peer.Conn, peerKey string) {
	defer e.wgConnWorker.Done()
	for {

		// randomize starting time a bit
		min := 500
		max := 2000
		duration := time.Duration(rand.Intn(max-min)+min) * time.Millisecond
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(duration):
		}

		// if peer has been removed -> give up
		if !e.peerExists(peerKey) {
			log.Debugf("peer %s doesn't exist anymore, won't retry connection", peerKey)
			return
		}

		if !e.signal.Ready() {
			log.Infof("signal client isn't ready, skipping connection attempt %s", peerKey)
			continue
		}

		// we might have received new STUN and TURN servers meanwhile, so update them
		e.syncMsgMux.Lock()
		conn.UpdateStunTurn(append(e.STUNs, e.TURNs...))
		e.syncMsgMux.Unlock()

		err := conn.Open(e.ctx)
		if err != nil {
			log.Debugf("connection to peer %s failed: %v", peerKey, err)
			var connectionClosedError *peer.ConnectionClosedError
			switch {
			case errors.As(err, &connectionClosedError):
				// conn has been forced to close, so we exit the loop
				return
			default:
			}
		}
	}
}

func (e *Engine) peerExists(peerKey string) bool {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	_, ok := e.peerConns[peerKey]
	return ok
}

func (e *Engine) createPeerConn(pubKey string, allowedIPs string) (*peer.Conn, error) {
	log.Debugf("creating peer connection %s", pubKey)
	var stunTurn []*stun.URI
	stunTurn = append(stunTurn, e.STUNs...)
	stunTurn = append(stunTurn, e.TURNs...)

	wgConfig := peer.WgConfig{
		RemoteKey:    pubKey,
		WgListenPort: e.config.WgPort,
		WgInterface:  e.wgInterface,
		AllowedIps:   allowedIPs,
		PreSharedKey: e.config.PreSharedKey,
	}

	if e.config.RosenpassEnabled && !e.config.RosenpassPermissive {
		lk := []byte(e.config.WgPrivateKey.PublicKey().String())
		rk := []byte(wgConfig.RemoteKey)
		var keyInput []byte
		if string(lk) > string(rk) {
			//nolint:gocritic
			keyInput = append(lk[:16], rk[:16]...)
		} else {
			//nolint:gocritic
			keyInput = append(rk[:16], lk[:16]...)
		}

		key, err := wgtypes.NewKey(keyInput)
		if err != nil {
			return nil, err
		}

		wgConfig.PreSharedKey = &key
	}

	// randomize connection timeout
	timeout := time.Duration(rand.Intn(PeerConnectionTimeoutMax-PeerConnectionTimeoutMin)+PeerConnectionTimeoutMin) * time.Millisecond
	config := peer.ConnConfig{
		Key:                  pubKey,
		LocalKey:             e.config.WgPrivateKey.PublicKey().String(),
		StunTurn:             stunTurn,
		InterfaceBlackList:   e.config.IFaceBlackList,
		DisableIPv6Discovery: e.config.DisableIPv6Discovery,
		Timeout:              timeout,
		UDPMux:               e.udpMux.UDPMuxDefault,
		UDPMuxSrflx:          e.udpMux,
		WgConfig:             wgConfig,
		LocalWgPort:          e.config.WgPort,
		NATExternalIPs:       e.parseNATExternalIPMappings(),
		UserspaceBind:        e.wgInterface.IsUserspaceBind(),
		RosenpassPubKey:      e.getRosenpassPubKey(),
		RosenpassAddr:        e.getRosenpassAddr(),
	}

	peerConn, err := peer.NewConn(config, e.statusRecorder, e.wgProxyFactory, e.mobileDep.TunAdapter, e.mobileDep.IFaceDiscover)
	if err != nil {
		return nil, err
	}

	wgPubKey, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return nil, err
	}

	signalOffer := func(offerAnswer peer.OfferAnswer) error {
		return SignalOfferAnswer(offerAnswer, e.config.WgPrivateKey, wgPubKey, e.signal, false)
	}

	signalCandidate := func(candidate ice.Candidate) error {
		return signalCandidate(candidate, e.config.WgPrivateKey, wgPubKey, e.signal)
	}

	signalAnswer := func(offerAnswer peer.OfferAnswer) error {
		return SignalOfferAnswer(offerAnswer, e.config.WgPrivateKey, wgPubKey, e.signal, true)
	}

	peerConn.SetSignalCandidate(signalCandidate)
	peerConn.SetSignalOffer(signalOffer)
	peerConn.SetSignalAnswer(signalAnswer)
	peerConn.SetSendSignalMessage(func(message *sProto.Message) error {
		return sendSignal(message, e.signal)
	})

	if e.rpManager != nil {

		peerConn.SetOnConnected(e.rpManager.OnConnected)
		peerConn.SetOnDisconnected(e.rpManager.OnDisconnected)
	}

	return peerConn, nil
}

// receiveSignalEvents connects to the Signal Service event stream to negotiate connection with remote peers
func (e *Engine) receiveSignalEvents() {
	go func() {
		// connect to a stream of messages coming from the signal server
		err := e.signal.Receive(e.ctx, func(msg *sProto.Message) error {
			e.syncMsgMux.Lock()
			defer e.syncMsgMux.Unlock()

			conn := e.peerConns[msg.Key]
			if conn == nil {
				return fmt.Errorf("wrongly addressed message %s", msg.Key)
			}

			switch msg.GetBody().Type {
			case sProto.Body_OFFER:
				remoteCred, err := signal.UnMarshalCredential(msg)
				if err != nil {
					return err
				}

				conn.RegisterProtoSupportMeta(msg.Body.GetFeaturesSupported())

				var rosenpassPubKey []byte
				rosenpassAddr := ""
				if msg.GetBody().GetRosenpassConfig() != nil {
					rosenpassPubKey = msg.GetBody().GetRosenpassConfig().GetRosenpassPubKey()
					rosenpassAddr = msg.GetBody().GetRosenpassConfig().GetRosenpassServerAddr()
				}
				conn.OnRemoteOffer(peer.OfferAnswer{
					IceCredentials: peer.IceCredentials{
						UFrag: remoteCred.UFrag,
						Pwd:   remoteCred.Pwd,
					},
					WgListenPort:    int(msg.GetBody().GetWgListenPort()),
					Version:         msg.GetBody().GetNetBirdVersion(),
					RosenpassPubKey: rosenpassPubKey,
					RosenpassAddr:   rosenpassAddr,
				})
			case sProto.Body_ANSWER:
				remoteCred, err := signal.UnMarshalCredential(msg)
				if err != nil {
					return err
				}

				conn.RegisterProtoSupportMeta(msg.GetBody().GetFeaturesSupported())

				var rosenpassPubKey []byte
				rosenpassAddr := ""
				if msg.GetBody().GetRosenpassConfig() != nil {
					rosenpassPubKey = msg.GetBody().GetRosenpassConfig().GetRosenpassPubKey()
					rosenpassAddr = msg.GetBody().GetRosenpassConfig().GetRosenpassServerAddr()
				}
				conn.OnRemoteAnswer(peer.OfferAnswer{
					IceCredentials: peer.IceCredentials{
						UFrag: remoteCred.UFrag,
						Pwd:   remoteCred.Pwd,
					},
					WgListenPort:    int(msg.GetBody().GetWgListenPort()),
					Version:         msg.GetBody().GetNetBirdVersion(),
					RosenpassPubKey: rosenpassPubKey,
					RosenpassAddr:   rosenpassAddr,
				})
			case sProto.Body_CANDIDATE:
				candidate, err := ice.UnmarshalCandidate(msg.GetBody().Payload)
				if err != nil {
					log.Errorf("failed on parsing remote candidate %s -> %s", candidate, err)
					return err
				}
				conn.OnRemoteCandidate(candidate)
			case sProto.Body_MODE:
			}

			return nil
		})
		if err != nil {
			// happens if signal is unavailable for a long time.
			// We want to cancel the operation of the whole client
			_ = CtxGetState(e.ctx).Wrap(ErrResetConnection)
			e.clientCancel()
			return
		}
	}()

	e.signal.WaitStreamConnected()
}

func (e *Engine) parseNATExternalIPMappings() []string {
	var mappedIPs []string
	var ignoredIFaces = make(map[string]interface{})
	for _, iFace := range e.config.IFaceBlackList {
		ignoredIFaces[iFace] = nil
	}
	for _, mapping := range e.config.NATExternalIPs {
		var external, internal string
		var externalIP, internalIP net.IP
		var err error

		split := strings.Split(mapping, "/")
		if len(split) > 2 {
			log.Warnf("ignoring invalid external mapping '%s', too many delimiters", mapping)
			break
		}
		if len(split) > 1 {
			internal = split[1]
			internalIP = net.ParseIP(internal)
			if internalIP == nil {
				// not a properly formatted IP address, maybe it's interface name?
				if _, present := ignoredIFaces[internal]; present {
					log.Warnf("internal interface '%s' in blacklist, ignoring external mapping '%s'", internal, mapping)
					break
				}
				internalIP, err = findIPFromInterfaceName(internal)
				if err != nil {
					log.Warnf("error finding interface IP for interface '%s', ignoring external mapping '%s': %v", internal, mapping, err)
					break
				}
			}
		}
		external = split[0]
		externalIP = net.ParseIP(external)
		if externalIP == nil {
			log.Warnf("invalid external IP, %s, ignoring external IP mapping '%s'", external, mapping)
			break
		}
		mappedIP := externalIP.String()
		if internalIP != nil {
			mappedIP = mappedIP + "/" + internalIP.String()
		}
		mappedIPs = append(mappedIPs, mappedIP)
		log.Infof("parsed external IP mapping of '%s' as '%s'", mapping, mappedIP)
	}
	if len(mappedIPs) != len(e.config.NATExternalIPs) {
		log.Warnf("one or more external IP mappings failed to parse, ignoring all mappings")
		return nil
	}
	return mappedIPs
}

func (e *Engine) close() {
	if e.wgProxyFactory != nil {
		if err := e.wgProxyFactory.Free(); err != nil {
			log.Errorf("failed closing ebpf proxy: %s", err)
		}
	}

	// stop/restore DNS first so dbus and friends don't complain because of a missing interface
	if e.dnsServer != nil {
		e.dnsServer.Stop()
		e.dnsServer = nil
	}

	if e.routeManager != nil {
		e.routeManager.Stop()
	}

	log.Debugf("removing Netbird interface %s", e.config.WgIfaceName)
	if e.wgInterface != nil {
		if err := e.wgInterface.Close(); err != nil {
			log.Errorf("failed closing Netbird interface %s %v", e.config.WgIfaceName, err)
		}
	}

	if !isNil(e.sshServer) {
		err := e.sshServer.Stop()
		if err != nil {
			log.Warnf("failed stopping the SSH server: %v", err)
		}
	}

	if e.firewall != nil {
		err := e.firewall.Reset()
		if err != nil {
			log.Warnf("failed to reset firewall: %s", err)
		}
	}

	if e.rpManager != nil {
		_ = e.rpManager.Close()
	}
}

func (e *Engine) readInitialSettings() ([]*route.Route, *nbdns.Config, error) {
	netMap, err := e.mgmClient.GetNetworkMap()
	if err != nil {
		return nil, nil, err
	}
	routes := toRoutes(netMap.GetRoutes())
	dnsCfg := toDNSConfig(netMap.GetDNSConfig())
	return routes, &dnsCfg, nil
}

func (e *Engine) newWgIface() (*iface.WGIface, error) {
	transportNet, err := e.newStdNet()
	if err != nil {
		log.Errorf("failed to create pion's stdnet: %s", err)
	}

	var mArgs *iface.MobileIFaceArguments
	switch runtime.GOOS {
	case "android":
		mArgs = &iface.MobileIFaceArguments{
			TunAdapter: e.mobileDep.TunAdapter,
			TunFd:      int(e.mobileDep.FileDescriptor),
		}
	case "ios":
		mArgs = &iface.MobileIFaceArguments{
			TunFd: int(e.mobileDep.FileDescriptor),
		}
	default:
	}

	return iface.NewWGIFace(e.config.WgIfaceName, e.config.WgAddr, e.config.WgAddr6, e.config.WgPort, e.config.WgPrivateKey.String(), iface.DefaultMTU, transportNet, mArgs)
}

func (e *Engine) wgInterfaceCreate() (err error) {
	switch runtime.GOOS {
	case "android":
		err = e.wgInterface.CreateOnAndroid(e.routeManager.InitialRouteRange(), e.dnsServer.DnsIP(), e.dnsServer.SearchDomains())
	case "ios":
		e.mobileDep.NetworkChangeListener.SetInterfaceIP(e.config.WgAddr)
		err = e.wgInterface.Create()
	default:
		err = e.wgInterface.Create()
	}
	return err
}

func (e *Engine) newDnsServer() ([]*route.Route, dns.Server, error) {
	// due to tests where we are using a mocked version of the DNS server
	if e.dnsServer != nil {
		return nil, e.dnsServer, nil
	}
	switch runtime.GOOS {
	case "android":
		routes, dnsConfig, err := e.readInitialSettings()
		if err != nil {
			return nil, nil, err
		}
		dnsServer := dns.NewDefaultServerPermanentUpstream(
			e.ctx,
			e.wgInterface,
			e.mobileDep.HostDNSAddresses,
			*dnsConfig,
			e.mobileDep.NetworkChangeListener,
			e.statusRecorder,
		)
		go e.mobileDep.DnsReadyListener.OnReady()
		return routes, dnsServer, nil
	case "ios":
		dnsServer := dns.NewDefaultServerIos(e.ctx, e.wgInterface, e.mobileDep.DnsManager, e.statusRecorder)
		return nil, dnsServer, nil
	default:
		dnsServer, err := dns.NewDefaultServer(e.ctx, e.wgInterface, e.config.CustomDNSAddress, e.statusRecorder)
		if err != nil {
			return nil, nil, err
		}
		return nil, dnsServer, nil
	}
}

// GetClientRoutes returns the current routes from the route map
func (e *Engine) GetClientRoutes() route.HAMap {
	return e.clientRoutes
}

// GetClientRoutesWithNetID returns the current routes from the route map, but the keys consist of the network ID only
func (e *Engine) GetClientRoutesWithNetID() map[route.NetID][]*route.Route {
	routes := make(map[route.NetID][]*route.Route, len(e.clientRoutes))
	for id, v := range e.clientRoutes {
		routes[id.NetID()] = v
	}
	return routes
}

// GetRouteManager returns the route manager
func (e *Engine) GetRouteManager() routemanager.Manager {
	return e.routeManager
}

func findIPFromInterfaceName(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	return findIPFromInterface(iface)
}

func findIPFromInterface(iface *net.Interface) (net.IP, error) {
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range ifaceAddrs {
		if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			return ipv4Addr, nil
		}
	}
	return nil, fmt.Errorf("interface %s don't have an ipv4 address", iface.Name)
}

func (e *Engine) getRosenpassPubKey() []byte {
	if e.rpManager != nil {
		return e.rpManager.GetPubKey()
	}
	return nil
}

func (e *Engine) getRosenpassAddr() string {
	if e.rpManager != nil {
		return e.rpManager.GetAddress().String()
	}
	return ""
}

func (e *Engine) receiveProbeEvents() {
	if e.signalProbe != nil {
		go e.signalProbe.Receive(e.ctx, func() bool {
			healthy := e.signal.IsHealthy()
			log.Debugf("received signal probe request, healthy: %t", healthy)
			return healthy
		})
	}

	if e.mgmProbe != nil {
		go e.mgmProbe.Receive(e.ctx, func() bool {
			healthy := e.mgmClient.IsHealthy()
			log.Debugf("received management probe request, healthy: %t", healthy)
			return healthy
		})
	}

	if e.relayProbe != nil {
		go e.relayProbe.Receive(e.ctx, func() bool {
			healthy := true

			results := append(e.probeSTUNs(), e.probeTURNs()...)
			e.statusRecorder.UpdateRelayStates(results)

			// A single failed server will result in a "failed" probe
			for _, res := range results {
				if res.Err != nil {
					healthy = false
					break
				}
			}

			log.Debugf("received relay probe request, healthy: %t", healthy)
			return healthy
		})
	}

	if e.wgProbe != nil {
		go e.wgProbe.Receive(e.ctx, func() bool {
			log.Debug("received wg probe request")

			for _, peer := range e.peerConns {
				key := peer.GetKey()
				wgStats, err := peer.GetConf().WgConfig.WgInterface.GetStats(key)
				if err != nil {
					log.Debugf("failed to get wg stats for peer %s: %s", key, err)
				}
				// wgStats could be zero value, in which case we just reset the stats
				if err := e.statusRecorder.UpdateWireGuardPeerState(key, wgStats); err != nil {
					log.Debugf("failed to update wg stats for peer %s: %s", key, err)
				}
			}

			return true
		})
	}
}

func (e *Engine) probeSTUNs() []relay.ProbeResult {
	return relay.ProbeAll(e.ctx, relay.ProbeSTUN, e.STUNs)
}

func (e *Engine) probeTURNs() []relay.ProbeResult {
	return relay.ProbeAll(e.ctx, relay.ProbeTURN, e.TURNs)
}

func (e *Engine) startNetworkMonitor() {
	if !e.config.NetworkMonitor {
		log.Infof("Network monitor is disabled, not starting")
		return
	}

	e.networkMonitor = networkmonitor.New()
	go func() {
		err := e.networkMonitor.Start(e.ctx, func() {
			log.Infof("Network monitor detected network change, restarting engine")
			if err := e.Stop(); err != nil {
				log.Errorf("Failed to stop engine: %v", err)
			}
			if err := e.Start(); err != nil {
				log.Errorf("Failed to start engine: %v", err)
			}
		})
		if err != nil && !errors.Is(err, networkmonitor.ErrStopped) {
			log.Errorf("Network monitor: %v", err)
		}
	}()
}
