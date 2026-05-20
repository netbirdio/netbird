package nftables

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"
)

const (
	externalMonitorReconcileDelay = 500 * time.Millisecond
	externalMonitorInitInterval   = 5 * time.Second
	externalMonitorMaxInterval    = 5 * time.Minute
	externalMonitorRandomization  = 0.5
)

// externalChainReconciler re-applies passthrough accept rules to external
// nftables chains. Implementations must be safe to call from the monitor
// goroutine; the Manager locks its mutex internally.
type externalChainReconciler interface {
	reconcileExternalChains() error
}

// externalChainMonitor watches nftables netlink events and triggers a
// reconcile when a new table or chain appears (e.g. after
// `firewall-cmd --reload`). Netlink errors trigger exponential-backoff
// reconnect.
type externalChainMonitor struct {
	reconciler externalChainReconciler

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func newExternalChainMonitor(r externalChainReconciler) *externalChainMonitor {
	return &externalChainMonitor{reconciler: r}
}

func (m *externalChainMonitor) start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})

	go m.run(ctx)
}

func (m *externalChainMonitor) stop() {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.done = nil
	m.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-done
}

func (m *externalChainMonitor) run(ctx context.Context) {
	defer close(m.done)

	bo := &backoff.ExponentialBackOff{
		InitialInterval:     externalMonitorInitInterval,
		RandomizationFactor: externalMonitorRandomization,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         externalMonitorMaxInterval,
		MaxElapsedTime:      0,
		Clock:               backoff.SystemClock,
	}
	bo.Reset()

	for ctx.Err() == nil {
		err := m.watch(ctx)
		if ctx.Err() != nil {
			return
		}

		delay := bo.NextBackOff()
		log.Warnf("external chain monitor: %v, reconnecting in %s", err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (m *externalChainMonitor) watch(ctx context.Context) error {
	events, closeMon, err := m.subscribe()
	if err != nil {
		return err
	}
	defer closeMon()

	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()

	pending := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-debounce.C:
			pending = false
			m.reconcile()
		case ev, ok := <-events:
			if !ok {
				return errors.New("monitor channel closed")
			}
			if ev.Error != nil {
				return fmt.Errorf("monitor event: %w", ev.Error)
			}
			if !isRelevantMonitorEvent(ev) {
				continue
			}
			resetDebounce(debounce, pending)
			pending = true
		}
	}
}

func (m *externalChainMonitor) subscribe() (chan *nftables.MonitorEvent, func(), error) {
	conn := &nftables.Conn{}
	mon := nftables.NewMonitor(
		nftables.WithMonitorAction(nftables.MonitorActionNew),
		nftables.WithMonitorObject(nftables.MonitorObjectChains|nftables.MonitorObjectTables),
	)
	events, err := conn.AddMonitor(mon)
	if err != nil {
		return nil, nil, fmt.Errorf("add netlink monitor: %w", err)
	}
	return events, func() { _ = mon.Close() }, nil
}

// resetDebounce reschedules a pending debounce timer without leaking a stale
// fire on its channel. pending must reflect whether the timer is armed.
func resetDebounce(t *time.Timer, pending bool) {
	if pending && !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(externalMonitorReconcileDelay)
}

func (m *externalChainMonitor) reconcile() {
	if err := m.reconciler.reconcileExternalChains(); err != nil {
		log.Warnf("reconcile external chain rules: %v", err)
	}
}

// isRelevantMonitorEvent returns true for table/chain creation events on
// families we care about. The reconciler filters to actual external filter
// chains.
func isRelevantMonitorEvent(ev *nftables.MonitorEvent) bool {
	switch ev.Type {
	case nftables.MonitorEventTypeNewChain:
		chain, ok := ev.Data.(*nftables.Chain)
		if !ok || chain == nil || chain.Table == nil {
			return false
		}
		return isMonitoredFamily(chain.Table.Family)
	case nftables.MonitorEventTypeNewTable:
		table, ok := ev.Data.(*nftables.Table)
		if !ok || table == nil {
			return false
		}
		return isMonitoredFamily(table.Family)
	}
	return false
}

func isMonitoredFamily(family nftables.TableFamily) bool {
	switch family {
	case nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyINet:
		return true
	}
	return false
}
