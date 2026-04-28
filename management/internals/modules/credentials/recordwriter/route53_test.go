package recordwriter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

// newRoute53TestWriter builds a route53Writer whose underlying SDK client
// uses the given roundTripFunc as its HTTP transport. retries are disabled
// so a single canned response is sufficient to drive the test.
func newRoute53TestWriter(rt roundTripFunc, hostedZoneID string) *route53Writer {
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIATEST", "secrettest", ""),
		HTTPClient:  &http.Client{Transport: rt},
		// Without this the SDK retries up to 3 times on 5xx, which
		// would consume our canned response and the next call would
		// return io.EOF.
		RetryMaxAttempts: 1,
	}
	return &route53Writer{
		client:       route53.NewFromConfig(cfg),
		hostedZoneID: hostedZoneID,
	}
}

// r53Resp builds a synthetic HTTP response. Route 53 returns XML; the
// SDK's deserializer is forgiving about which root element is used as
// long as the child element names match the document grammar.
func r53Resp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// XML envelope fragments. Real Route 53 envelopes include xmlns; the SDK
// doesn't validate the namespace, so we omit it for brevity.
const (
	xmlListHostedZonesEmpty = `<ListHostedZonesResponse>
  <HostedZones></HostedZones>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
  <Marker></Marker>
</ListHostedZonesResponse>`

	xmlChangeRRSetsOK = `<ChangeResourceRecordSetsResponse>
  <ChangeInfo>
    <Id>/change/C123</Id>
    <Status>PENDING</Status>
    <SubmittedAt>2026-04-28T00:00:00Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>`

	xmlListRRSetsEmpty = `<ListResourceRecordSetsResponse>
  <ResourceRecordSets></ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>`
)

func xmlListHostedZones(zones map[string]string) string {
	var b strings.Builder
	b.WriteString("<ListHostedZonesResponse><HostedZones>")
	for id, name := range zones {
		b.WriteString("<HostedZone><Id>/hostedzone/")
		b.WriteString(id)
		b.WriteString("</Id><Name>")
		b.WriteString(name)
		b.WriteString("</Name><CallerReference>x</CallerReference></HostedZone>")
	}
	b.WriteString("</HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems><Marker></Marker></ListHostedZonesResponse>")
	return b.String()
}

func xmlListRRSetsCNAME(name, target string) string {
	return `<ListResourceRecordSetsResponse>
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>` + name + `</Name>
      <Type>CNAME</Type>
      <TTL>300</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>` + target + `</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>`
}

// xmlAccessDeniedError mimics what Route 53 returns when the credential
// authenticates but isn't authorized. AWS error envelopes use either an
// <ErrorResponse> or <Response><Errors><Error>...</Error></Errors></Response>
// shape; smithy parses both via GetErrorResponseComponents.
const xmlAccessDeniedError = `<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User is not authorized to perform this action</Message>
  </Error>
  <RequestId>req-1</RequestId>
</ErrorResponse>`

const xmlNoSuchHostedZoneError = `<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>NoSuchHostedZone</Code>
    <Message>Zone does not exist</Message>
  </Error>
  <RequestId>req-2</RequestId>
</ErrorResponse>`

func TestRoute53Writer_BuildRequiresKeys(t *testing.T) {
	if _, err := buildRoute53Writer(map[string]string{}); err == nil {
		t.Fatal("expected error for missing access_key_id")
	}
	if _, err := buildRoute53Writer(map[string]string{"access_key_id": "x"}); err == nil {
		t.Fatal("expected error for missing secret_access_key")
	}
	if _, err := buildRoute53Writer(map[string]string{
		"access_key_id":     "x",
		"secret_access_key": "y",
	}); err != nil {
		t.Fatalf("unexpected error with both keys: %v", err)
	}
	// Optional fields shouldn't break construction.
	if _, err := buildRoute53Writer(map[string]string{
		"access_key_id":     "x",
		"secret_access_key": "y",
		"region":            "eu-west-1",
		"hosted_zone_id":    "Z123",
		"session_token":     "tok",
	}); err != nil {
		t.Fatalf("unexpected error with optional fields: %v", err)
	}
}

func TestRoute53Writer_RegistersAtInit(t *testing.T) {
	if _, err := BuildRecordWriter("route53", map[string]string{
		"access_key_id":     "x",
		"secret_access_key": "y",
	}); err != nil {
		t.Fatalf("expected route53 to be registered: %v", err)
	}
}

func TestRoute53Writer_WriteCNAME_PinnedZone(t *testing.T) {
	calls := []string{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		switch {
		case strings.Contains(req.URL.Path, "/hostedzone/Z-PINNED/rrset") && req.Method == http.MethodGet:
			return r53Resp(200, xmlListRRSetsEmpty), nil
		case strings.Contains(req.URL.Path, "/hostedzone/Z-PINNED/rrset") && req.Method == http.MethodPost:
			return r53Resp(200, xmlChangeRRSetsOK), nil
		case strings.Contains(req.URL.Path, "/hostedzone"):
			t.Errorf("unexpected hostedzone list when zone is pinned: %s", req.URL.Path)
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "Z-PINNED")
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range calls {
		if strings.HasSuffix(c, "/hostedzone") || strings.HasSuffix(c, "/hostedzone/") {
			t.Fatalf("pinned zone path should skip hostedzone listing, got: %v", calls)
		}
	}
}

func TestRoute53Writer_WriteCNAME_DiscoversZone(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/hostedzone") &&
			!strings.Contains(req.URL.Path, "/rrset"):
			return r53Resp(200, xmlListHostedZones(map[string]string{
				"ZEXAMPLE": "example.com.",
			})), nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/rrset"):
			return r53Resp(200, xmlListRRSetsEmpty), nil
		case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/rrset"):
			return r53Resp(200, xmlChangeRRSetsOK), nil
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "")
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoute53Writer_WriteCNAME_IdempotentMatch(t *testing.T) {
	wrote := false
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/rrset"):
			return r53Resp(200, xmlListRRSetsCNAME("*.app.example.com.", "us-east.proxy.netbird.io")), nil
		case req.Method == http.MethodPost:
			wrote = true
			return r53Resp(200, xmlChangeRRSetsOK), nil
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "Z-PINNED")
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrote {
		t.Fatal("idempotent path must not POST when target already matches")
	}
}

func TestRoute53Writer_WriteCNAME_Conflict(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/rrset") {
			return r53Resp(200, xmlListRRSetsCNAME("*.app.example.com.", "someone-else.example.net")), nil
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "Z-PINNED")
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrRecordExists) {
		t.Fatalf("expected ErrRecordExists, got %v", err)
	}
}

func TestRoute53Writer_WriteCNAME_ZoneNotFound(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// User has zones, but none matches example.com.
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/hostedzone") {
			return r53Resp(200, xmlListHostedZones(map[string]string{
				"ZOTHER": "other.com.",
			})), nil
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "")
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestRoute53Writer_WriteCNAME_AccessDenied(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// First call (zone listing) gets AccessDenied — common when the
		// credential has DNS-01 _acme-challenge scope only.
		return r53Resp(403, xmlAccessDeniedError), nil
	})

	w := newRoute53TestWriter(rt, "")
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestRoute53Writer_WriteCNAME_NoSuchHostedZone(t *testing.T) {
	// Hosted zone is pinned but the SDK returns NoSuchHostedZone — the
	// pinned ID is stale. We expose this as ErrZoneNotFound so the
	// dashboard can advise the user to refresh the credential.
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return r53Resp(404, xmlNoSuchHostedZoneError), nil
	})

	w := newRoute53TestWriter(rt, "Z-STALE")
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestRoute53Writer_DeleteCNAME_Idempotent(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/rrset") {
			return r53Resp(200, xmlListRRSetsEmpty), nil
		}
		if req.Method == http.MethodPost {
			t.Errorf("delete on missing record should not POST a change")
			return r53Resp(500, ""), nil
		}
		return r53Resp(404, ""), nil
	})

	w := newRoute53TestWriter(rt, "Z-PINNED")
	if err := w.DeleteCNAME(context.Background(), "*.app.example.com"); err != nil {
		t.Fatalf("delete on missing record should be no-op, got %v", err)
	}
}
