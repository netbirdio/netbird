package domain_test

import (
	"context"
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
