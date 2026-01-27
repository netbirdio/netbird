package rosenpass

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	rp "cunicu.li/go-rosenpass"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultLog         = slog.LevelInfo
	defaultLogLevelVar = "NB_ROSENPASS_LOG_LEVEL"
)

func hashRosenpassKey(key []byte) string {
	hasher := sha256.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

type Manager struct {
	ifaceName    string
	spk          []byte
	ssk          []byte
	rpKeyHash    string
	preSharedKey *[32]byte
	rpPeerIDs    map[string]*rp.PeerID
	rpWgHandler  *NetbirdHandler
	server       *rp.Server
	lock         sync.Mutex
	port         int
	wgIface      PresharedKeySetter
}

// NewManager creates a new Rosenpass manager
func NewManager(preSharedKey *wgtypes.Key, wgIfaceName string) (*Manager, error) {
	public, secret, err := rp.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	rpKeyHash := hashRosenpassKey(public)
	log.Tracef("generated new rosenpass key pair with public key %s", rpKeyHash)
	return &Manager{ifaceName: wgIfaceName, rpKeyHash: rpKeyHash, spk: public, ssk: secret, preSharedKey: (*[32]byte)(preSharedKey), rpPeerIDs: make(map[string]*rp.PeerID), lock: sync.Mutex{}}, nil
}

func (m *Manager) GetPubKey() []byte {
	return m.spk
}

// GetAddress returns the address of the Rosenpass server
func (m *Manager) GetAddress() *net.UDPAddr {
	return &net.UDPAddr{Port: m.port}
}

// addPeer adds a new peer to the Rosenpass server
func (m *Manager) addPeer(rosenpassPubKey []byte, rosenpassAddr string, wireGuardIP string, wireGuardPubKey string) error {
	var err error
	pcfg := rp.PeerConfig{PublicKey: rosenpassPubKey}
	if m.preSharedKey != nil {
		pcfg.PresharedKey = *m.preSharedKey
	}
	if bytes.Compare(m.spk, rosenpassPubKey) == 1 {
		_, strPort, err := net.SplitHostPort(rosenpassAddr)
		if err != nil {
			return fmt.Errorf("failed to parse rosenpass address: %w", err)
		}
		peerAddr := fmt.Sprintf("%s:%s", wireGuardIP, strPort)
		if pcfg.Endpoint, err = net.ResolveUDPAddr("udp", peerAddr); err != nil {
			return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
		}
	}
	peerID, err := m.server.AddPeer(pcfg)
	if err != nil {
		return err
	}

	key, err := wgtypes.ParseKey(wireGuardPubKey)
	if err != nil {
		return err
	}
	m.rpWgHandler.AddPeer(peerID, m.ifaceName, rp.Key(key))
	m.rpPeerIDs[wireGuardPubKey] = &peerID
	return nil
}

// removePeer removes a peer from the Rosenpass server
func (m *Manager) removePeer(wireGuardPubKey string) error {
	err := m.server.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	if err != nil {
		return err
	}
	m.rpWgHandler.RemovePeer(*m.rpPeerIDs[wireGuardPubKey])
	return nil
}

func (m *Manager) generateConfig() (rp.Config, error) {
	opts := &slog.HandlerOptions{
		Level: getLogLevel(),
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	cfg := rp.Config{Logger: logger}

	cfg.PublicKey = m.spk
	cfg.SecretKey = m.ssk

	cfg.Peers = []rp.PeerConfig{}

	m.lock.Lock()
	m.rpWgHandler = NewNetbirdHandler()
	if m.wgIface != nil {
		m.rpWgHandler.SetInterface(m.wgIface)
	}
	m.lock.Unlock()

	cfg.Handlers = []rp.Handler{m.rpWgHandler}

	port, err := findRandomAvailableUDPPort()
	if err != nil {
		log.Errorf("could not determine a random port for rosenpass server. Error: %s", err)
		return rp.Config{}, err
	}

	m.port = port

	cfg.ListenAddrs = []*net.UDPAddr{m.GetAddress()}

	return cfg, nil
}

func getLogLevel() slog.Level {
	level, ok := os.LookupEnv(defaultLogLevelVar)
	if !ok {
		return defaultLog
	}
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		log.Warnf("unknown log level: %s. Using default %s", level, defaultLog.String())
		return defaultLog
	}
}

func (m *Manager) OnDisconnected(peerKey string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.rpPeerIDs[peerKey]; !ok {
		// if we didn't have this peer yet, just skip
		return
	}

	err := m.removePeer(peerKey)
	if err != nil {
		log.Error("failed to remove rosenpass peer", err)
	}

	delete(m.rpPeerIDs, peerKey)
}

// Run starts the Rosenpass server
func (m *Manager) Run() error {
	conf, err := m.generateConfig()
	if err != nil {
		return err
	}

	m.server, err = rp.NewUDPServer(conf)
	if err != nil {
		return err
	}

	log.Infof("starting rosenpass server on port %d", m.port)

	return m.server.Run()
}

// Close closes the Rosenpass server
func (m *Manager) Close() error {
	if m.server != nil {
		err := m.server.Close()
		if err != nil {
			log.Errorf("failed closing local rosenpass server")
		}
		m.server = nil
	}
	return nil
}

// SetInterface sets the WireGuard interface for the rosenpass handler.
// This can be called before or after Run() - the interface will be stored
// and passed to the handler when it's created or updated immediately if
// already running.
func (m *Manager) SetInterface(iface PresharedKeySetter) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.wgIface = iface
	if m.rpWgHandler != nil {
		m.rpWgHandler.SetInterface(iface)
	}
}

// OnConnected is a handler function that is triggered when a connection to a remote peer establishes
func (m *Manager) OnConnected(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if remoteRosenpassPubKey == nil {
		log.Warnf("remote peer with public key %s does not support rosenpass", remoteWireGuardKey)
		return
	}

	rpKeyHash := hashRosenpassKey(remoteRosenpassPubKey)
	log.Debugf("received remote rosenpass key %s, my key %s", rpKeyHash, m.rpKeyHash)

	err := m.addPeer(remoteRosenpassPubKey, remoteRosenpassAddr, wireGuardIP, remoteWireGuardKey)
	if err != nil {
		log.Errorf("failed to add rosenpass peer: %s", err)
		return
	}
}

// IsPresharedKeyInitialized returns true if Rosenpass has completed a handshake
// and set a PSK for the given WireGuard peer.
func (m *Manager) IsPresharedKeyInitialized(wireGuardPubKey string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	peerID, ok := m.rpPeerIDs[wireGuardPubKey]
	if !ok || peerID == nil {
		return false
	}

	return m.rpWgHandler.IsPeerInitialized(*peerID)
}

func findRandomAvailableUDPPort() (int, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("could not find an available UDP port: %w", err)
	}
	defer conn.Close()

	splitAddress := strings.Split(conn.LocalAddr().String(), ":")
	return strconv.Atoi(splitAddress[len(splitAddress)-1])
}
