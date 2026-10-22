package grpc

import (
	"context"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

const (
	// A peer fetches each country of a route once when it installs the route, from both the
	// route handler and the route ACL, and a route has at most 32 countries. A response can hold
	// hundreds of thousands of prefixes, so a peer gets that many fetches at once and few more.
	countryPrefixesBurst       = 64
	countryPrefixesInterval    = 2 * time.Second
	countryPrefixesIdleTimeout = 10 * time.Minute
)

// countryPrefixesLimiter limits how often each peer can fetch country prefixes. The zero value
// is ready to use.
type countryPrefixesLimiter struct {
	mu          sync.Mutex
	peers       map[string]*countryPrefixesBudget
	nextCleanup time.Time
}

type countryPrefixesBudget struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

func (l *countryPrefixesLimiter) allow(peerKey string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !now.Before(l.nextCleanup) {
		for key, budget := range l.peers {
			if now.Sub(budget.lastUsed) >= countryPrefixesIdleTimeout {
				delete(l.peers, key)
			}
		}
		l.nextCleanup = now.Add(countryPrefixesIdleTimeout)
	}

	budget := l.peers[peerKey]
	if budget == nil {
		if l.peers == nil {
			l.peers = make(map[string]*countryPrefixesBudget)
		}
		budget = &countryPrefixesBudget{limiter: rate.NewLimiter(rate.Every(countryPrefixesInterval), countryPrefixesBurst)}
		l.peers[peerKey] = budget
	}
	budget.lastUsed = now
	return budget.limiter.AllowN(now, 1)
}

// SetGeolocation sets the geolocation service that resolves country routes. It must be called
// before the server starts serving.
func (s *Server) SetGeolocation(geo geolocation.Geolocation) {
	s.geo = geo
}

// GetCountryPrefixes returns the IP prefixes the geolocation database assigns to a country.
func (s *Server) GetCountryPrefixes(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	countryReq := &proto.CountryPrefixesRequest{}
	peerKey, err := s.parseRequest(ctx, req, countryReq)
	if err != nil {
		return nil, err
	}

	if _, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String()); err != nil {
		if e, ok := internalStatus.FromError(err); ok && e.Type() == internalStatus.NotFound {
			return nil, status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		return nil, status.Errorf(codes.Internal, "lookup peer")
	}

	// Checked after the peer lookup, so only registered peers get a budget.
	if !s.countryPrefixesLimiter.allow(peerKey.String(), time.Now()) {
		return nil, status.Errorf(codes.ResourceExhausted, "too many country prefix requests")
	}

	country := strings.ToUpper(countryReq.GetCountry())
	if !geolocation.IsCountryCode(country) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid country code %q", countryReq.GetCountry())
	}

	if s.geo == nil {
		return nil, status.Errorf(codes.Unavailable, "geolocation is disabled")
	}

	prefixes, err := s.geo.CountryPrefixes(country)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get prefixes of country %s: %v", country, err)
		return nil, status.Errorf(codes.Unavailable, "geolocation database is not available")
	}

	resp := &proto.CountryPrefixesResponse{Prefixes: make([]string, 0, len(prefixes))}
	for _, prefix := range prefixes {
		resp.Prefixes = append(resp.Prefixes, prefix.String())
	}
	return s.encryptResponse(peerKey, resp)
}
