//go:build windows

package systemops

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortRouteCandidates(t *testing.T) {
	tests := []struct {
		name       string
		candidates []candidateRoute
		wantOrder  []uint32
	}{
		{
			name: "longest prefix wins over metrics",
			candidates: []candidateRoute{
				{interfaceIndex: 1, prefixLength: 0, routeMetric: 0, interfaceMetric: 5},
				{interfaceIndex: 2, prefixLength: 24, routeMetric: 100, interfaceMetric: 50},
			},
			wantOrder: []uint32{2, 1},
		},
		{
			// Windows ranks equal-length prefixes by route metric + interface metric,
			// so a higher route metric on a low metric interface can still win.
			name: "combined metric beats route metric alone",
			candidates: []candidateRoute{
				{interfaceIndex: 8, prefixLength: 0, routeMetric: 0, interfaceMetric: 100},
				{interfaceIndex: 5, prefixLength: 0, routeMetric: 10, interfaceMetric: 5},
			},
			wantOrder: []uint32{5, 8},
		},
		{
			name: "lower combined metric wins",
			candidates: []candidateRoute{
				{interfaceIndex: 5, prefixLength: 0, routeMetric: 300, interfaceMetric: 5},
				{interfaceIndex: 8, prefixLength: 0, routeMetric: 0, interfaceMetric: 100},
			},
			wantOrder: []uint32{8, 5},
		},
		{
			name: "equal combined metric falls back to route metric",
			candidates: []candidateRoute{
				{interfaceIndex: 1, prefixLength: 0, routeMetric: 20, interfaceMetric: 10},
				{interfaceIndex: 2, prefixLength: 0, routeMetric: 5, interfaceMetric: 25},
			},
			wantOrder: []uint32{2, 1},
		},
		{
			// The metrics are uint32 on the Windows side, so the sum must not wrap.
			name: "combined metric beyond the uint32 range",
			candidates: []candidateRoute{
				{interfaceIndex: 1, prefixLength: 0, routeMetric: math.MaxUint32, interfaceMetric: 5},
				{interfaceIndex: 2, prefixLength: 0, routeMetric: math.MaxUint32 - 10, interfaceMetric: 5},
			},
			wantOrder: []uint32{2, 1},
		},
		{
			name: "unknown interface metric ranks on route metric only",
			candidates: []candidateRoute{
				{interfaceIndex: 1, prefixLength: 0, routeMetric: 30, interfaceMetric: -1},
				{interfaceIndex: 2, prefixLength: 0, routeMetric: 5, interfaceMetric: 10},
			},
			wantOrder: []uint32{2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortRouteCandidates(tt.candidates)

			got := make([]uint32, 0, len(tt.candidates))
			for _, c := range tt.candidates {
				got = append(got, c.interfaceIndex)
			}
			assert.Equal(t, tt.wantOrder, got)
		})
	}
}
