//go:build !android

package dns

import (
	"fmt"
	"testing"
)

func Test_mergeSearchDomains(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"c", "d"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 4 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 4)
	}
}

func Test_mergeSearchTooMuchDomains(t *testing.T) {
	searchDomains := []string{"a", "b", "c", "d", "e", "f", "g"}
	originDomains := []string{"h", "i"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooMuchDomainsInOrigin(t *testing.T) {
	searchDomains := []string{"a", "b"}
	originDomains := []string{"c", "d", "e", "f", "g"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 6 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 6)
	}
}

func Test_mergeSearchTooLongDomain(t *testing.T) {
	searchDomains := []string{getLongLine()}
	originDomains := []string{"b"}
	mergedDomains := mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}

	searchDomains = []string{"b"}
	originDomains = []string{getLongLine()}

	mergedDomains = mergeSearchDomains(searchDomains, originDomains)
	if len(mergedDomains) != 1 {
		t.Errorf("invalid len of result domains: %d, want: %d", len(mergedDomains), 1)
	}
}

func Test_isContains(t *testing.T) {
	type args struct {
		subList []string
		list    []string
	}
	tests := []struct {
		args args
		want bool
	}{
		{
			args: args{
				subList: []string{"a", "b", "c"},
				list:    []string{"a", "b", "c"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{"a"},
				list:    []string{"a", "b", "c"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{"d"},
				list:    []string{"a", "b", "c"},
			},
			want: false,
		},
		{
			args: args{
				subList: []string{"a"},
				list:    []string{},
			},
			want: false,
		},
		{
			args: args{
				subList: []string{},
				list:    []string{"b"},
			},
			want: true,
		},
		{
			args: args{
				subList: []string{},
				list:    []string{},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run("list check test", func(t *testing.T) {
			if got := isContains(tt.args.subList, tt.args.list); got != tt.want {
				t.Errorf("isContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func getLongLine() string {
	x := "search "
	for {
		for i := 0; i <= 9; i++ {
			if len(x) > fileMaxLineCharsLimit {
				return x
			}
			x = fmt.Sprintf("%s%d", x, i)
		}
	}
}
