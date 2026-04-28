package recordwriter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// route53Writer implements RecordWriter against AWS Route 53. It uses the
// official aws-sdk-go-v2 client because Route 53's request signing is non-
// trivial (SigV4) and re-implementing it raw would be error-prone — unlike
// Cloudflare and DigitalOcean which take a bearer token over HTTPS.
//
// Mirrors the credential field names accepted by the cert-issuance path
// (proxy/internal/acme/legoclient/provider_route53.go) so a single saved
// credential works for both DNS-01 challenges and CNAME writes.
type route53Writer struct {
	client       *route53.Client
	hostedZoneID string // optional pre-pinned zone; skips lookup when set
}

func init() {
	registerRecordWriter("route53", buildRoute53Writer)
}

// buildRoute53Writer constructs a Route 53 writer from a credential field
// map. Required: "access_key_id", "secret_access_key". Optional: "region",
// "hosted_zone_id", "session_token". Field names match
// provider_route53.go so a credential record stored for cert issuance
// works here unchanged.
func buildRoute53Writer(secret map[string]string) (RecordWriter, error) {
	accessKey := secret["access_key_id"]
	if accessKey == "" {
		return nil, fmt.Errorf("route53 credential is missing required field %q", "access_key_id")
	}
	secretKey := secret["secret_access_key"]
	if secretKey == "" {
		return nil, fmt.Errorf("route53 credential is missing required field %q", "secret_access_key")
	}
	region := secret["region"]
	if region == "" {
		// Route 53 is a global service, but the v2 SDK still needs a
		// region for endpoint resolution. us-east-1 is the canonical
		// default the AWS docs use for global services.
		region = "us-east-1"
	}
	cfg := aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, secret["session_token"]),
	}
	return &route53Writer{
		client:       route53.NewFromConfig(cfg),
		hostedZoneID: secret["hosted_zone_id"],
	}, nil
}

func (w *route53Writer) WriteCNAME(ctx context.Context, fqdn, target string, ttl int) error {
	zoneID, err := w.resolveZone(ctx, fqdn)
	if err != nil {
		return err
	}

	existing, err := w.findCNAME(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	if existing != "" {
		if normalizeCNAMETarget(existing) == normalizeCNAMETarget(target) {
			return nil // idempotent: same target already in place
		}
		return ErrRecordExists
	}

	ttl64 := int64(ttl)
	_, err = w.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{{
				// CREATE (not UPSERT) on purpose: we already verified
				// no record exists at this name, and CREATE will fail
				// loudly via InvalidChangeBatch if a TOCTOU race put
				// one there between the list and the change. UPSERT
				// would silently overwrite a different target.
				Action: r53types.ChangeActionCreate,
				ResourceRecordSet: &r53types.ResourceRecordSet{
					Name: aws.String(fqdn),
					Type: r53types.RRTypeCname,
					TTL:  &ttl64,
					ResourceRecords: []r53types.ResourceRecord{
						{Value: aws.String(target)},
					},
				},
			}},
		},
	})
	if err != nil {
		return mapRoute53Error(err)
	}
	return nil
}

func (w *route53Writer) DeleteCNAME(ctx context.Context, fqdn string) error {
	zoneID, err := w.resolveZone(ctx, fqdn)
	if err != nil {
		if errors.Is(err, ErrZoneNotFound) {
			return nil // missing zone → missing record → success
		}
		return err
	}

	existing, err := w.findCNAMERecordSet(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	if existing == nil {
		return nil // already absent
	}

	_, err = w.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{{
				Action:            r53types.ChangeActionDelete,
				ResourceRecordSet: existing,
			}},
		},
	})
	if err != nil {
		return mapRoute53Error(err)
	}
	return nil
}

// resolveZone returns a hosted zone ID for the FQDN. If the credential
// pins hosted_zone_id we use that directly — paginating zone lists can
// be slow for accounts with hundreds of zones, and the user has already
// told us which one they want. Otherwise paginate ListHostedZones and
// pick the longest apex candidate that matches.
func (w *route53Writer) resolveZone(ctx context.Context, fqdn string) (string, error) {
	if w.hostedZoneID != "" {
		return w.hostedZoneID, nil
	}

	candidates := apexCandidates(fqdn)
	// Build a set for O(1) membership; we still preserve longest-first
	// preference by iterating candidates in order at the end.
	candidateSet := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		candidateSet[c] = true
	}

	matches := map[string]string{} // candidate → zoneID
	paginator := route53.NewListHostedZonesPaginator(w.client, &route53.ListHostedZonesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", mapRoute53Error(err)
		}
		for _, hz := range page.HostedZones {
			if hz.Name == nil || hz.Id == nil {
				continue
			}
			// Route 53 zone names always end with a dot.
			zoneName := strings.TrimSuffix(*hz.Name, ".")
			if candidateSet[zoneName] {
				if _, seen := matches[zoneName]; !seen {
					matches[zoneName] = *hz.Id
				}
			}
		}
	}

	// Walk candidates longest-first; first match wins.
	for _, c := range candidates {
		if id, ok := matches[c]; ok {
			return id, nil
		}
	}
	return "", ErrZoneNotFound
}

// findCNAME returns the CNAME target string at fqdn, or empty string if
// none. Use findCNAMERecordSet when you need the full record (for
// reconstructing a DELETE change).
func (w *route53Writer) findCNAME(ctx context.Context, zoneID, fqdn string) (string, error) {
	rs, err := w.findCNAMERecordSet(ctx, zoneID, fqdn)
	if err != nil {
		return "", err
	}
	if rs == nil || len(rs.ResourceRecords) == 0 || rs.ResourceRecords[0].Value == nil {
		return "", nil
	}
	return *rs.ResourceRecords[0].Value, nil
}

// findCNAMERecordSet looks up the CNAME at fqdn by asking ListResource-
// RecordSets to start at exactly that name+type and taking 1 result. If
// the first result is something else (different name, different type),
// the record doesn't exist and we return nil.
func (w *route53Writer) findCNAMERecordSet(ctx context.Context, zoneID, fqdn string) (*r53types.ResourceRecordSet, error) {
	wantName := strings.TrimSuffix(fqdn, ".") + "."
	one := int32(1)
	out, err := w.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(wantName),
		StartRecordType: r53types.RRTypeCname,
		MaxItems:        &one,
	})
	if err != nil {
		return nil, mapRoute53Error(err)
	}
	if len(out.ResourceRecordSets) == 0 {
		return nil, nil
	}
	rs := out.ResourceRecordSets[0]
	if rs.Type != r53types.RRTypeCname {
		return nil, nil
	}
	if rs.Name == nil || strings.TrimSuffix(*rs.Name, ".") != strings.TrimSuffix(fqdn, ".") {
		return nil, nil
	}
	return &rs, nil
}

// mapRoute53Error translates AWS SDK errors into the package's sentinel
// errors. Falls through to surfacing the raw error wrapped — the
// management layer's error mapper logs and surfaces those as generic
// "provider error" responses.
func mapRoute53Error(err error) error {
	if err == nil {
		return nil
	}

	// Concrete typed errors first — these are the cases the SDK fully
	// models. errors.As walks the wrap chain (OperationError wraps the
	// typed error) so we don't have to unwrap manually.
	var nshz *r53types.NoSuchHostedZone
	if errors.As(err, &nshz) {
		return ErrZoneNotFound
	}
	var icb *r53types.InvalidChangeBatch
	if errors.As(err, &icb) {
		// The only way we hit InvalidChangeBatch from a CREATE is a
		// TOCTOU race where another writer added a record at the
		// same name between our list and our change. Treat as
		// conflict so the caller gets a meaningful error.
		return ErrRecordExists
	}
	var prnc *r53types.PriorRequestNotComplete
	if errors.As(err, &prnc) {
		return ErrProviderRateLimited
	}
	var thr *r53types.ThrottlingException
	if errors.As(err, &thr) {
		return ErrProviderRateLimited
	}
	var invIn *r53types.InvalidInput
	if errors.As(err, &invIn) {
		return fmt.Errorf("route53 invalid input: %w", err)
	}
	var invArg *r53types.InvalidArgument
	if errors.As(err, &invArg) {
		return fmt.Errorf("route53 invalid argument: %w", err)
	}

	// HTTP-status-based mapping. Some errors (notably AccessDenied)
	// arrive as a smithy.GenericAPIError with no concrete type — we
	// have to inspect status / error code by hand.
	var respErr *smithyhttp.ResponseError
	status := 0
	if errors.As(err, &respErr) {
		status = respErr.HTTPStatusCode()
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch code {
		case "AccessDenied", "AccessDeniedException", "NotAuthorizedException", "UnauthorizedOperation":
			return ErrInsufficientScope
		case "Throttling", "ThrottlingException", "TooManyRequestsException", "RequestThrottled":
			return ErrProviderRateLimited
		}
	}

	switch {
	case status == http.StatusForbidden, status == http.StatusUnauthorized:
		return ErrInsufficientScope
	case status == http.StatusTooManyRequests:
		return ErrProviderRateLimited
	case status >= 500:
		return ErrProviderUnavailable
	}

	// Network-layer failure (no HTTP response). Treat as upstream
	// unavailable so the caller can advise retry.
	if respErr == nil && apiErr == nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return fmt.Errorf("route53: %w", err)
}
