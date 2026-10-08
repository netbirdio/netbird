package domain_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
)

type resolver struct {
	CNAME string
}

func (r resolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return r.CNAME, nil
}

func TestIsValid(t *testing.T) {
	tests := map[string]struct {
		resolver interface {
			LookupCNAME(context.Context, string) (string, error)
		}
		domain string
		accept []string
		expect bool
	}{
		"match": {
			resolver: resolver{"bar.example.com."}, // Including trailing "." in response.
			domain:   "foo.example.com",
			accept:   []string{"bar.example.com"},
			expect:   true,
		},
		"no match": {
			resolver: resolver{"invalid"},
			domain:   "foo.example.com",
			accept:   []string{"bar.example.com"},
			expect:   false,
		},
		"accept trailing dot": {
			resolver: resolver{"bar.example.com."},
			domain:   "foo.example.com",
			accept:   []string{"bar.example.com."}, // Including trailing "." in accept.
			expect:   true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			validator := domain.NewValidator(test.resolver)
			actual := validator.IsValid(t.Context(), test.domain, test.accept)
			if test.expect != actual {
				t.Errorf("Incorrect return value:\nexpect: %v\nactual: %v", test.expect, actual)
			}
		})
	}
}

type errResolver struct {
	err error
}

func (r errResolver) LookupCNAME(context.Context, string) (string, error) {
	return "", r.err
}

func TestValidate_Reason(t *testing.T) {
	const notFound = "no CNAME record found for validation.foo.example.com; point it to eu.proxy.example.com"
	tests := map[string]struct {
		resolver interface {
			LookupCNAME(context.Context, string) (string, error)
		}
		reason  domain.ValidationReason
		message string
	}{
		"mismatch": {
			resolver: resolver{"other.example.net."},
			reason:   domain.ValidationReasonCNAMEMismatch,
			message:  "CNAME record validation.foo.example.com points to other.example.net; point it to eu.proxy.example.com",
		},
		"no cname resolves to itself": {
			resolver: resolver{"validation.foo.example.com."},
			reason:   domain.ValidationReasonCNAMENotFound,
			message:  notFound,
		},
		"not found": {
			resolver: errResolver{&net.DNSError{Err: "no such host", Name: "validation.foo.example.com", Server: "10.0.0.2:53", IsNotFound: true}},
			reason:   domain.ValidationReasonCNAMENotFound,
			message:  notFound,
		},
		"other error is not forwarded": {
			resolver: errResolver{errors.New("dial udp 10.0.0.2:53: connect: network is unreachable")},
			reason:   domain.ValidationReasonLookupFailed,
			message:  "DNS lookup for validation.foo.example.com failed; retry the validation",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := domain.NewValidator(test.resolver).Validate(t.Context(), "foo.example.com", []string{"eu.proxy.example.com"})
			var vErr *domain.ValidationError
			if !errors.As(err, &vErr) {
				t.Fatalf("expected a *domain.ValidationError, got %v", err)
			}
			if vErr.Reason != test.reason || vErr.Message != test.message {
				t.Errorf("expect %q %q, actual %q %q", test.reason, test.message, vErr.Reason, vErr.Message)
			}
		})
	}
}
