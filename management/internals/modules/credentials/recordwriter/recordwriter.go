// Package recordwriter writes DNS records on a provider's zone using a
// stored credential. It is invoked by the auto-configure custom-domain
// flow in the management server to create the wildcard CNAME pointing at
// a NetBird proxy cluster, without asking the user to manage DNS by hand.
//
// This package is intentionally distinct from
// proxy/internal/acme/legoclient (the cert-issuance Lego DNS-01 path).
// The two packages share credential field names (see secretpayload) but
// their runtime clients differ — Lego's challenge.Provider surface is
// challenge-shaped (Present/CleanUp for _acme-challenge TXT) and doesn't
// fit CNAME writes cleanly. Each provider here constructs its own
// minimal API client (raw HTTP for Cloudflare/DigitalOcean, AWS SDK for
// Route 53, miekg/dns for RFC 2136).
package recordwriter

import (
	"context"
	"errors"
	"fmt"
)

// RecordWriter writes and removes DNS records on a provider's zone using
// a stored credential. Used by the auto-configure custom domain flow to
// create the wildcard CNAME pointing at a NetBird proxy cluster, without
// asking the user to manage DNS records by hand.
//
// This is intentionally separate from challenge.Provider (the Lego DNS-01
// challenge interface). Lego's surface is challenge-shaped (Present/CleanUp
// for _acme-challenge TXT records); CNAME writes don't fit cleanly through
// it. Implementations construct their own SDK or HTTP client from the same
// decoded credential map (see secretpayload.Decode) used by the Lego
// providers — the credential record is shared, the runtime client isn't.
type RecordWriter interface {
	// WriteCNAME writes (or updates idempotently) a CNAME at fqdn pointing
	// to target with the given TTL. Implementations resolve the apex zone
	// from fqdn internally — Cloudflare needs a zone ID, Route 53 a hosted
	// zone ID; the manager layer should not know about that.
	//
	// If a CNAME already exists at fqdn pointing at target, return nil
	// (idempotent). If it points elsewhere, return ErrRecordExists.
	WriteCNAME(ctx context.Context, fqdn, target string, ttl int) error

	// DeleteCNAME removes the CNAME at fqdn. A missing record is not an
	// error.
	DeleteCNAME(ctx context.Context, fqdn string) error
}

// RecordWriterBuilder constructs a RecordWriter from a decoded credential
// field map. Each builder validates its required keys and constructs the
// underlying API client.
type RecordWriterBuilder func(secret map[string]string) (RecordWriter, error)

// recordWriterRegistry maps DNS provider type identifiers to their writer
// builders. Populated by init() in each provider's *_writer.go file.
//
// Keep in sync with management/internals/modules/credentials/providertypes
// (source of truth for accepted provider type strings) and with the Lego
// challenge.Provider registry in providers.go.
var recordWriterRegistry = map[string]RecordWriterBuilder{}

// registerRecordWriter is called from each provider's init() to add itself
// to the registry. Centralized in this file so the registry map stays
// unexported.
func registerRecordWriter(name string, b RecordWriterBuilder) {
	recordWriterRegistry[name] = b
}

// BuildRecordWriter returns a configured RecordWriter for the named
// provider. Returns a clear error if auto-configure is not supported for
// that provider (e.g., a provider supported for cert issuance via the
// Custom Provider escape-hatch but without a writer implementation).
func BuildRecordWriter(name string, secret map[string]string) (RecordWriter, error) {
	b, ok := recordWriterRegistry[name]
	if !ok {
		return nil, fmt.Errorf("auto-configure not supported for DNS provider %q", name)
	}
	return b(secret)
}

// Sentinel errors. The manager layer maps these to HTTP status codes and
// structured error_code values for the dashboard. See
// management/internals/modules/reverseproxy/domain/manager/errors.go.
var (
	// ErrZoneNotFound means none of the apex candidates derived from the
	// FQDN matched a zone the credential can see.
	ErrZoneNotFound = errors.New("zone not found for domain")

	// ErrRecordExists means a CNAME already exists at the FQDN with a
	// different target. Auto-configure refuses to overwrite.
	ErrRecordExists = errors.New("conflicting record exists")

	// ErrInsufficientScope means the credential authenticates correctly
	// but doesn't have permission to read the zone or write the record.
	// Common when users carry over cert-issuance tokens that were
	// scoped to _acme-challenge only.
	ErrInsufficientScope = errors.New("credential lacks zone-write scope")

	// ErrProviderRateLimited means the provider returned a rate-limit
	// response. The dashboard advises the user to retry later.
	ErrProviderRateLimited = errors.New("provider rate limited")

	// ErrProviderUnavailable means the provider's API was unreachable
	// or returned a 5xx.
	ErrProviderUnavailable = errors.New("provider unavailable")
)
