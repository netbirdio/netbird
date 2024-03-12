package healthcheck

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const HealthCheckInterval = 10 * time.Second

type Scheduler struct {
	peerConns *map[string]*peer.Conn
	stopChan  chan bool
	wg        sync.WaitGroup
	isRunning bool
	ticker    *time.Ticker
}

func NewScheduler(peerConns *map[string]*peer.Conn) *Scheduler {
	return &Scheduler{
		peerConns: peerConns,
		stopChan:  make(chan bool),
	}
}

func (s *Scheduler) Start() {
	if s.isRunning {
		log.Trace("Scheduler is already running.")
		return
	}
	log.Debugf("Starting health check scheduler.")
	s.isRunning = true
	s.ticker = time.NewTicker(HealthCheckInterval)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.ticker.C:
				s.checkPeers()
			case <-s.stopChan:
				log.Debugf("Stopping health check scheduler.")
				return
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	if !s.isRunning {
		log.Trace("Scheduler is not running.")
		return
	}
	s.ticker.Stop()
	s.stopChan <- true
	s.wg.Wait()
	s.isRunning = false
}

func (s *Scheduler) checkPeers() {
	log.Debugf("Running health checks: %d", len(*s.peerConns))
	for _, conn := range *s.peerConns {
		log.Debugf("Running health check for peer %s", conn.GetKey())
		go conn.HealthCheck()
	}
}
