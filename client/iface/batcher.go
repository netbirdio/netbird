package iface

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/device"
)

const (
	// DefaultBatchFlushInterval is the default maximum time to wait before flushing batched operations
	DefaultBatchFlushInterval = 300 * time.Millisecond
	// DefaultBatchSizeThreshold is the default number of operations to trigger an immediate flush
	DefaultBatchSizeThreshold = 100

	// AllowedIPOpAdd represents an add operation
	AllowedIPOpAdd = "add"
	// AllowedIPOpRemove represents a remove operation
	AllowedIPOpRemove = "remove"

	EnvDisableWGBatching      = "NB_DISABLE_WG_BATCHING"
	EnvWGBatchFlushIntervalMS = "NB_WG_BATCH_FLUSH_INTERVAL_MS"
	EnvWGBatchSizeThreshold   = "NB_WG_BATCH_SIZE_THRESHOLD"
)

// AllowedIPOperation represents a pending allowed IP operation
type AllowedIPOperation struct {
	PeerKey   string
	Prefix    netip.Prefix
	Operation string
}

// PeerUpdateOperation represents a pending peer update operation
type PeerUpdateOperation struct {
	PeerKey      string
	AllowedIPs   []netip.Prefix
	KeepAlive    time.Duration
	Endpoint     *net.UDPAddr
	PreSharedKey *wgtypes.Key
}

// WGBatcher batches WireGuard configuration updates to reduce syscall overhead
type WGBatcher struct {
	configurer device.WGConfigurer
	mu         sync.Mutex

	allowedIPOps []AllowedIPOperation
	peerUpdates  map[string]*PeerUpdateOperation

	flushTimer *time.Timer
	flushChan  chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	batchFlushInterval time.Duration
	batchSizeThreshold int
}

// NewWGBatcher creates a new WireGuard operation batcher
func NewWGBatcher(configurer device.WGConfigurer) *WGBatcher {
	if os.Getenv(EnvDisableWGBatching) != "" {
		log.Infof("WireGuard allowed IP batching disabled via %s", EnvDisableWGBatching)
		return nil
	}

	flushInterval := DefaultBatchFlushInterval
	sizeThreshold := DefaultBatchSizeThreshold

	if intervalMs := os.Getenv(EnvWGBatchFlushIntervalMS); intervalMs != "" {
		if ms, err := strconv.Atoi(intervalMs); err == nil && ms > 0 {
			flushInterval = time.Duration(ms) * time.Millisecond
			log.Infof("WireGuard batch flush interval set to %v", flushInterval)
		}
	}

	if threshold := os.Getenv(EnvWGBatchSizeThreshold); threshold != "" {
		if size, err := strconv.Atoi(threshold); err == nil && size > 0 {
			sizeThreshold = size
			log.Infof("WireGuard batch size threshold set to %d", sizeThreshold)
		}
	}

	log.Info("WireGuard allowed IP batching enabled")

	ctx, cancel := context.WithCancel(context.Background())
	b := &WGBatcher{
		configurer:         configurer,
		peerUpdates:        make(map[string]*PeerUpdateOperation),
		flushChan:          make(chan struct{}, 1),
		ctx:                ctx,
		cancel:             cancel,
		batchFlushInterval: flushInterval,
		batchSizeThreshold: sizeThreshold,
	}

	b.wg.Add(1)
	go b.flushLoop()

	return b
}

// Close stops the batcher and flushes any pending operations
func (b *WGBatcher) Close() error {
	b.mu.Lock()
	if b.flushTimer != nil {
		b.flushTimer.Stop()
	}
	b.mu.Unlock()

	b.cancel()

	if err := b.Flush(); err != nil {
		log.Errorf("failed to flush pending operations on close: %v", err)
	}

	b.wg.Wait()

	return nil
}

// UpdatePeer batches a peer update operation
func (b *WGBatcher) UpdatePeer(peerKey string, allowedIPs []netip.Prefix, keepAlive time.Duration, endpoint *net.UDPAddr, preSharedKey *wgtypes.Key) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.peerUpdates[peerKey] = &PeerUpdateOperation{
		PeerKey:      peerKey,
		AllowedIPs:   allowedIPs,
		KeepAlive:    keepAlive,
		Endpoint:     endpoint,
		PreSharedKey: preSharedKey,
	}

	b.scheduleFlush()
	return nil
}

// AddAllowedIP batches an allowed IP addition
func (b *WGBatcher) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.allowedIPOps = append(b.allowedIPOps, AllowedIPOperation{
		PeerKey:   peerKey,
		Prefix:    allowedIP,
		Operation: AllowedIPOpAdd,
	})

	b.scheduleFlush()
	return nil
}

// RemoveAllowedIP batches an allowed IP removal
func (b *WGBatcher) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.allowedIPOps = append(b.allowedIPOps, AllowedIPOperation{
		PeerKey:   peerKey,
		Prefix:    allowedIP,
		Operation: AllowedIPOpRemove,
	})

	b.scheduleFlush()
	return nil
}

// Flush immediately processes all batched operations
func (b *WGBatcher) Flush() error {
	b.mu.Lock()

	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.flushTimer = nil
	}

	peerUpdates := b.peerUpdates
	allowedIPOps := b.allowedIPOps

	b.peerUpdates = make(map[string]*PeerUpdateOperation)
	b.allowedIPOps = nil

	b.mu.Unlock()

	return b.processBatch(peerUpdates, allowedIPOps)
}

// scheduleFlush schedules a batch flush if not already scheduled
func (b *WGBatcher) scheduleFlush() {
	shouldFlushNow := len(b.allowedIPOps)+len(b.peerUpdates) >= b.batchSizeThreshold

	if shouldFlushNow {
		select {
		case b.flushChan <- struct{}{}:
		default:
		}
		return
	}

	if b.flushTimer == nil {
		b.flushTimer = time.AfterFunc(b.batchFlushInterval, func() {
			select {
			case b.flushChan <- struct{}{}:
			default:
			}
		})
	}
}

// flushLoop handles periodic flushing of batched operations
func (b *WGBatcher) flushLoop() {
	defer b.wg.Done()

	for {
		select {
		case <-b.flushChan:
			if err := b.Flush(); err != nil {
				log.Errorf("Error flushing WireGuard operations: %v", err)
			}
		case <-b.ctx.Done():
			return
		}
	}
}

// processBatch processes a batch of operations
func (b *WGBatcher) processBatch(peerUpdates map[string]*PeerUpdateOperation, allowedIPOps []AllowedIPOperation) error {
	if len(peerUpdates) == 0 && len(allowedIPOps) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start)
		log.Debugf("Processed batch of %d peer updates and %d allowed IP operations in %v",
			len(peerUpdates), len(allowedIPOps), duration)
	}()

	var merr *multierror.Error

	if err := b.processPeerUpdates(peerUpdates); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := b.processAllowedIPOps(allowedIPOps); err != nil {
		merr = multierror.Append(merr, err)
	}

	return nberrors.FormatErrorOrNil(merr)
}

// processPeerUpdates processes peer update operations
func (b *WGBatcher) processPeerUpdates(peerUpdates map[string]*PeerUpdateOperation) error {
	var merr *multierror.Error
	for _, update := range peerUpdates {
		if err := b.configurer.UpdatePeer(
			update.PeerKey,
			update.AllowedIPs,
			update.KeepAlive,
			update.Endpoint,
			update.PreSharedKey,
		); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("update peer %s: %w", update.PeerKey, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// processAllowedIPOps processes allowed IP add/remove operations
func (b *WGBatcher) processAllowedIPOps(allowedIPOps []AllowedIPOperation) error {
	peerChanges := b.groupAllowedIPChanges(allowedIPOps)
	return b.applyAllowedIPChanges(peerChanges)
}

// groupAllowedIPChanges groups allowed IP operations by peer
func (b *WGBatcher) groupAllowedIPChanges(allowedIPOps []AllowedIPOperation) map[string]struct {
	toAdd    []netip.Prefix
	toRemove []netip.Prefix
} {
	peerChanges := make(map[string]struct {
		toAdd    []netip.Prefix
		toRemove []netip.Prefix
	})

	for _, op := range allowedIPOps {
		changes := peerChanges[op.PeerKey]
		if op.Operation == AllowedIPOpAdd {
			changes.toAdd = append(changes.toAdd, op.Prefix)
		} else {
			changes.toRemove = append(changes.toRemove, op.Prefix)
		}
		peerChanges[op.PeerKey] = changes
	}

	return peerChanges
}

// applyAllowedIPChanges applies allowed IP changes for each peer
func (b *WGBatcher) applyAllowedIPChanges(peerChanges map[string]struct {
	toAdd    []netip.Prefix
	toRemove []netip.Prefix
}) error {
	var merr *multierror.Error

	for peerKey, changes := range peerChanges {
		for _, prefix := range changes.toRemove {
			if err := b.configurer.RemoveAllowedIP(peerKey, prefix); err != nil {
				if errors.Is(err, configurer.ErrPeerNotFound) || errors.Is(err, configurer.ErrAllowedIPNotFound) {
					log.Debugf("remove allowed IP %s for peer %s: %v", prefix, peerKey, err)
				} else {
					merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s for peer %s: %w", prefix, peerKey, err))
				}
			}
		}

		for _, prefix := range changes.toAdd {
			if err := b.configurer.AddAllowedIP(peerKey, prefix); err != nil {
				merr = multierror.Append(merr, fmt.Errorf("add allowed IP %s for peer %s: %w", prefix, peerKey, err))
			}
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}
