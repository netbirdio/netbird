package server

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const jobChannelBufferSize = 100

type PeersJobManager struct {
	jobRequestChannels  map[string]chan *proto.JobRequest
	jobResponseChannels map[string]chan *proto.JobResponse
	channelsMux         *sync.RWMutex
	metrics             telemetry.AppMetrics
}

// NewPeersJobManager returns a new instance of PeersJobManager
func NewPeersJobManager(metrics telemetry.AppMetrics) *PeersJobManager {
	return &PeersJobManager{
		jobRequestChannels:  make(map[string]chan *proto.JobRequest),
		jobResponseChannels: make(map[string]chan *proto.JobResponse),
		channelsMux:         &sync.RWMutex{},
		metrics:             metrics,
	}
}

// ---------------------------
// Job Requests (Management → Client)
// ---------------------------

// CreateJob sends a job request to the peer's channel
func (p *PeersJobManager) CreateJob(ctx context.Context, peerID string, job *proto.JobRequest) {
	p.channelsMux.RLock()
	channel, ok := p.jobRequestChannels[peerID]
	p.channelsMux.RUnlock()

	if !ok {
		log.WithContext(ctx).Debugf("peer %s has no request channel", peerID)
		return
	}

	select {
	case channel <- job:
		log.WithContext(ctx).Debugf("job request sent to peer %s", peerID)
	default:
		log.WithContext(ctx).Warnf("request channel for peer %s is full or closed", peerID)
	}
}

// CreateRequestChannel creates a new request channel for a peer
func (p *PeersJobManager) CreateRequestChannel(ctx context.Context, peerID string) chan *proto.JobRequest {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()

	if ch, ok := p.jobRequestChannels[peerID]; ok {
		delete(p.jobRequestChannels, peerID)
		close(ch)
	}

	ch := make(chan *proto.JobRequest, channelBufferSize)
	p.jobRequestChannels[peerID] = ch

	log.WithContext(ctx).Debugf("opened request channel for peer %s", peerID)
	return ch
}

// GetRequestChannel returns the request channel for a peer
func (p *PeersJobManager) GetRequestChannel(peerID string) chan *proto.JobRequest {
	p.channelsMux.RLock()
	defer p.channelsMux.RUnlock()
	return p.jobRequestChannels[peerID]
}

// ---------------------------
// Job Responses (Client → Management)
// ---------------------------

// SendResponse sends a job response from the client to management
func (p *PeersJobManager) SendResponse(ctx context.Context, peerID string, resp *proto.JobResponse) {
	p.channelsMux.RLock()
	channel, ok := p.jobResponseChannels[peerID]
	p.channelsMux.RUnlock()

	if !ok {
		log.WithContext(ctx).Debugf("peer %s has no response channel", peerID)
		return
	}

	select {
	case channel <- resp:
		log.WithContext(ctx).Debugf("job response sent from peer %s", peerID)
	default:
		log.WithContext(ctx).Warnf("response channel for peer %s is full or closed", peerID)
	}
}

// CreateResponseChannel creates a new response channel for a peer
func (p *PeersJobManager) CreateResponseChannel(ctx context.Context, peerID string) chan *proto.JobResponse {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()

	if ch, ok := p.jobResponseChannels[peerID]; ok {
		delete(p.jobResponseChannels, peerID)
		close(ch)
	}

	ch := make(chan *proto.JobResponse, channelBufferSize)
	p.jobResponseChannels[peerID] = ch

	log.WithContext(ctx).Debugf("opened response channel for peer %s", peerID)
	return ch
}

// GetResponseChannel returns the response channel for a peer
func (p *PeersJobManager) GetResponseChannel(peerID string) chan *proto.JobResponse {
	p.channelsMux.RLock()
	defer p.channelsMux.RUnlock()
	return p.jobResponseChannels[peerID]
}

// ---------------------------
// Channel Closing
// ---------------------------

func (p *PeersJobManager) CloseRequestChannel(ctx context.Context, peerID string) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	if ch, ok := p.jobRequestChannels[peerID]; ok {
		close(ch)
		delete(p.jobRequestChannels, peerID)
		log.WithContext(ctx).Debugf("closed request channel for peer %s", peerID)
	}
}

func (p *PeersJobManager) CloseResponseChannel(ctx context.Context, peerID string) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	if ch, ok := p.jobResponseChannels[peerID]; ok {
		close(ch)
		delete(p.jobResponseChannels, peerID)
		log.WithContext(ctx).Debugf("closed response channel for peer %s", peerID)
	}
}

// Close all channels
func (p *PeersJobManager) CloseAllChannels(ctx context.Context) {
	p.channelsMux.Lock()
	defer p.channelsMux.Unlock()
	for peerID, ch := range p.jobRequestChannels {
		close(ch)
		delete(p.jobRequestChannels, peerID)
	}
	for peerID, ch := range p.jobResponseChannels {
		close(ch)
		delete(p.jobResponseChannels, peerID)
	}
	log.WithContext(ctx).Debugf("all request and response channels closed")
}
