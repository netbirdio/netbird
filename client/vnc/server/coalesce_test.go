//go:build !js && !ios && !android

package server

import (
	"reflect"
	"testing"
)

func TestCoalesceRects(t *testing.T) {
	cases := []struct {
		name string
		in   [][4]int
		want [][4]int
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "single",
			in:   [][4]int{{0, 0, 64, 64}},
			want: [][4]int{{0, 0, 64, 64}},
		},
		{
			name: "horizontal_run",
			in:   [][4]int{{0, 0, 64, 64}, {64, 0, 64, 64}, {128, 0, 64, 64}},
			want: [][4]int{{0, 0, 192, 64}},
		},
		{
			name: "vertical_run",
			in:   [][4]int{{0, 0, 64, 64}, {0, 64, 64, 64}, {0, 128, 64, 64}},
			want: [][4]int{{0, 0, 64, 192}},
		},
		{
			name: "block_2x2",
			in: [][4]int{
				{0, 0, 64, 64}, {64, 0, 64, 64},
				{0, 64, 64, 64}, {64, 64, 64, 64},
			},
			want: [][4]int{{0, 0, 128, 128}},
		},
		{
			name: "no_merge_gap",
			in:   [][4]int{{0, 0, 64, 64}, {192, 0, 64, 64}},
			want: [][4]int{{0, 0, 64, 64}, {192, 0, 64, 64}},
		},
		{
			name: "two_disjoint_columns",
			in: [][4]int{
				{0, 0, 64, 64}, {192, 0, 64, 64},
				{0, 64, 64, 64}, {192, 64, 64, 64},
			},
			want: [][4]int{{0, 0, 64, 128}, {192, 0, 64, 128}},
		},
		{
			name: "misaligned_widths_no_vertical_merge",
			in: [][4]int{
				{0, 0, 128, 64},
				{0, 64, 64, 64},
			},
			want: [][4]int{{0, 0, 128, 64}, {0, 64, 64, 64}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := coalesceRects(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
