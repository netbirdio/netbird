package nftables

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
)

func TestBuildLegacyRouteRuleExpressions(t *testing.T) {
	sourcePayload := &expr.Payload{}
	sourceCmp := &expr.Cmp{}
	destinationPayload := &expr.Payload{}
	destinationCmp := &expr.Cmp{}
	nilSourceDestination := &expr.Payload{}
	nilDestinationSource := &expr.Cmp{}

	tests := []struct {
		name        string
		source      []expr.Any
		destination []expr.Any
		matches     []expr.Any
	}{
		{
			name:        "both non-empty",
			source:      []expr.Any{sourcePayload, sourceCmp},
			destination: []expr.Any{destinationPayload, destinationCmp},
			matches:     []expr.Any{sourcePayload, sourceCmp, destinationPayload, destinationCmp},
		},
		{
			name:        "nil source",
			destination: []expr.Any{nilSourceDestination},
			matches:     []expr.Any{nilSourceDestination},
		},
		{
			name:    "nil destination",
			source:  []expr.Any{nilDestinationSource},
			matches: []expr.Any{nilDestinationSource},
		},
		{
			name: "both nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLegacyRouteRuleExpressions(tt.source, tt.destination)

			require.Len(t, got, len(tt.matches)+2)
			for i, match := range tt.matches {
				require.Same(t, match, got[i])
			}

			require.IsType(t, &expr.Counter{}, got[len(tt.matches)])
			verdict, ok := got[len(tt.matches)+1].(*expr.Verdict)
			require.True(t, ok)
			require.Equal(t, expr.VerdictAccept, verdict.Kind)
		})
	}
}
