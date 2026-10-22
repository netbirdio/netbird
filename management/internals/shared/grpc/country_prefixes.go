package grpc

import (
	"context"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

const (
	// Installing a route fetches each of its countries once from the route handler and once from
	// the route ACL. A budget per country lets a peer install routes for any number of countries
	// at once, while fetching one country, up to hundreds of thousands of prefixes, stays limited.
	countryPrefixesBurst       = 4
	countryPrefixesInterval    = 30 * time.Second
	countryPrefixesIdleTimeout = 10 * time.Minute
)

// countryPrefixesKey identifies the budget of one peer for one country.
type countryPrefixesKey struct {
	peer    wgtypes.Key
	country string
}

// countryPrefixesLimiter limits how often each peer can fetch the prefixes of each country. The
// zero value is ready to use.
type countryPrefixesLimiter struct {
	mu          sync.Mutex
	budgets     map[countryPrefixesKey]*countryPrefixesBudget
	nextCleanup time.Time
}

type countryPrefixesBudget struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

func (l *countryPrefixesLimiter) allow(key countryPrefixesKey, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !now.Before(l.nextCleanup) {
		for k, budget := range l.budgets {
			if now.Sub(budget.lastUsed) >= countryPrefixesIdleTimeout {
				delete(l.budgets, k)
			}
		}
		l.nextCleanup = now.Add(countryPrefixesIdleTimeout)
	}

	budget := l.budgets[key]
	if budget == nil {
		if l.budgets == nil {
			l.budgets = make(map[countryPrefixesKey]*countryPrefixesBudget)
		}
		budget = &countryPrefixesBudget{limiter: rate.NewLimiter(rate.Every(countryPrefixesInterval), countryPrefixesBurst)}
		l.budgets[key] = budget
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

	country := strings.ToUpper(countryReq.GetCountry())
	if !geolocation.IsCountryCode(country) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid country code %q", countryReq.GetCountry())
	}

	// Checked after the peer lookup and the code check, so only registered peers get budgets,
	// and only for valid codes.
	if !s.countryPrefixesLimiter.allow(countryPrefixesKey{peer: peerKey, country: country}, time.Now()) {
		return nil, status.Errorf(codes.ResourceExhausted, "too many prefix requests for country %s", country)
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
