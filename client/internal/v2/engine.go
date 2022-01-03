package v2

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/client/internal/v2/event"
	"github.com/wiretrustee/wiretrustee/client/internal/v2/peer"
	"github.com/wiretrustee/wiretrustee/iface"
	management "github.com/wiretrustee/wiretrustee/management/client"
	mgmProto "github.com/wiretrustee/wiretrustee/management/proto"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	sProto "github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"time"
)

// EngineConfig is a config for the Engine
type EngineConfig struct {
	WgIface string
	// WgAddr is a Wireguard local address (Wiretrustee Network IP)
	WgAddr string
	// WgPrivateKey is a Wireguard private key of our peer (it MUST never leave the machine)
	WgPrivateKey wgtypes.Key
	// IFaceBlackList is a list of network interfaces to ignore when discovering connection candidates (ICE related)
	IFaceBlackList map[string]struct{}

	PreSharedKey *wgtypes.Key

	ctx context.Context
}

type Engine struct {
	config *EngineConfig
	WgPort int
	state  *State
	// bus is an eventbus channel that Engine uses to coordinate execution
	bus chan event.Event

	signalClient *signal.Client
	mgmtClient   *management.Client
}

func (engine *Engine) Stop() error {
	return nil
}

func (engine *Engine) Start() error {

	err := engine.configureWireguard()
	if err != nil {
		return err
	}

	go engine.runWorker()

	//todo
	engine.receiveSignalEvents()
	engine.receiveManagementEvents()

	return nil
}

func (engine *Engine) runWorker() {

	for {
		select {
		case <-engine.config.ctx.Done():
			log.Debugf("engine context done, worker stopped")
			return
		case e := <-engine.bus:
			log.Debugf("received a new event %s", e.Type().String())
			err := engine.handleEvent(e)
			if err != nil {
				engine.handleError(err)
				continue
			}
		}
	}

}

func (engine *Engine) handleError(err error) {
	//todo
	log.Errorf("engine error: %v", err)
}

func (engine *Engine) handleEvent(e event.Event) error {

	switch e.Type() {
	case event.ConnectedToManagement:
		//noop
		return nil
	case event.ConnectedToSignal:
		return engine.handleConnectedToSignal(e)
	case event.PeerConnected:
		return engine.handlePeerConnected(e)
	case event.PeerDisconnected:
		return engine.handlePeerDisconnected(e)
	case event.ReceivedManagementUpdate:
		return engine.handleManagementUpdate(e)
	case event.ReceivedSignal:
		return nil
	}

	return nil
}

func (engine *Engine) handleManagementUpdate(e event.Event) error {
	update := e.Data().(*mgmProto.SyncResponse)
	if update.GetWiretrusteeConfig() != nil {
		err := engine.updateTURNs(update.GetWiretrusteeConfig().GetTurns())
		if err != nil {
			return err
		}

		err = engine.updateSTUNs(update.GetWiretrusteeConfig().GetStuns())
		if err != nil {
			return err
		}

		//todo update signal
	}

	if update.GetRemotePeers() != nil || update.GetRemotePeersIsEmpty() {
		// empty arrays are serialized by protobuf to null, but for our case empty array is a valid state.
		err := engine.updatePeers(update.GetRemotePeers())
		if err != nil {
			return err
		}
	}

	return nil
}

func (engine *Engine) handlePeerConnected(e event.Event) error {
	peerKey := e.Data().(string)

	p := engine.state.GetPeer(peerKey)
	if p == nil {
		log.Warnf("event %s - peer %s doesn't exist, skipping", e.Type().String(), peerKey)
		return nil
	}

	if p.Status() != peer.StatusConnected {
		log.Warnf("event %s - peer %s is not connected, skipping", e.Type().String(), peerKey)
		return nil
	}

	return nil
}

func (engine *Engine) handlePeerDisconnected(e event.Event) error {
	peerKey := e.Data().(string)

	p := engine.state.GetPeer(peerKey)
	if p == nil {
		log.Warnf("event %s - peer %s doesn't exist, skipping", e.Type().String(), peerKey)
		return nil
	}

	if p.Status() != peer.StatusDisconnected {
		log.Warnf("event %s - peer %s is not disconnected, skipping", e.Type().String(), peerKey)
		return nil
	}

	if !engine.signalClient.StreamConnected() {
		log.Warnf("event %s - signal is not connected, skipping peer %s", e.Type().String(), peerKey)
		return nil
	}

	go func() {
		err := p.Open()
		if err != nil {
			log.Debugf("failed opening connection to peer %s", peerKey)
			engine.FireDelayedEvent(time.Second, event.New(event.PeerDisconnected, peerKey))
		}
	}()

	return nil
}

func (engine *Engine) handleConnectedToSignal(e event.Event) error {
	for key, p := range engine.state.peerMap {
		switch p.Status() {
		case peer.StatusDisconnected:
			log.Debugf("peer %s is disconnected, trigering connection", key)
			engine.FireEvent(event.New(event.PeerDisconnected, key))
		default:
			log.Debugf("event %s - peer %s is in %s status", e.Type().String(), key, p.Status())
			continue
		}
	}

	return nil
}

// FireEvent fires an event placing it to the Engine.bus channel asynchronously in a goroutine
// returned channel is closed when event has been fired
func (engine *Engine) FireEvent(e event.Event) chan struct{} {
	return engine.FireDelayedEvent(0*time.Millisecond, e)
}

// FireDelayedEvent fires an event delayed by timeout placing it to the Engine.bus channel asynchronously in a goroutine
// returned channel is closed when event has been fired
func (engine *Engine) FireDelayedEvent(timeout time.Duration, e event.Event) chan struct{} {
	log.Debugf("firing a delayed event %s after %s", e.Type().String(), timeout.String())
	fired := make(chan struct{})
	go func() {
		time.Sleep(timeout)
		engine.bus <- e
		log.Debugf("fired a delayed event %s after %s", e.Type().String(), timeout.String())
		close(fired)
	}()
	return fired
}

func (engine *Engine) configureWireguard() error {
	wgIface := engine.config.WgIface
	wgAddr := engine.config.WgAddr
	myPrivateKey := engine.config.WgPrivateKey

	err := iface.Create(wgIface, wgAddr)
	if err != nil {
		log.Errorf("failed creating interface %s: [%s]", wgIface, err.Error())
		return err
	}

	err = iface.Configure(wgIface, myPrivateKey.String())
	if err != nil {
		log.Errorf("failed configuring Wireguard interface [%s]: %s", wgIface, err.Error())
		return err
	}

	port, err := iface.GetListenPort(wgIface)
	if err != nil {
		log.Errorf("failed getting Wireguard listen port [%s]: %s", wgIface, err.Error())
		return err
	}
	engine.WgPort = *port

	return nil
}

// receiveManagementEvents connects to the Management Service event stream to receive updates from the management service
func (engine *Engine) receiveManagementEvents() {
	go func() {
		err := engine.mgmtClient.Sync(func(update *mgmProto.SyncResponse) error {
			<-engine.FireEvent(event.New(event.ReceivedManagementUpdate, update))
			return nil
		})
		if err != nil {
			// happens if management is unavailable for a long time.
			// We want to cancel the operation of the whole client
			//engine.cancel()
			return
		}
		log.Debugf("stopped receiving updates from Management Service")
	}()
	log.Debugf("connecting to Management Service updates stream")
}

// receiveSignalEvents connects to the Signal Service event stream to negotiate connection with remote peers
func (engine *Engine) receiveSignalEvents() {

	go func() {
		// connect to a stream of messages coming from the signal server
		err := engine.signalClient.Receive(func(msg *sProto.Message) error {
			<-engine.FireEvent(event.New(event.ReceivedSignal, msg))
			return nil
		})
		if err != nil {
			// happens if signal is unavailable for a long time.
			// We want to cancel the operation of the whole client
			//engine.cancel()
			return
		}
	}()

	engine.signalClient.WaitStreamConnected()
}
