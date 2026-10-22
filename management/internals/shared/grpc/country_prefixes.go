package grpc

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

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
