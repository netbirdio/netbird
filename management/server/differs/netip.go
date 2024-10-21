package differs

import (
	"fmt"
	"net/netip"
	"reflect"

	"github.com/r3labs/diff/v3"
)

// NetIPAddr is a custom differ for netip.Addr
type NetIPAddr struct {
	DiffFunc func(path []string, a, b reflect.Value, p interface{}) error
}

func (differ NetIPAddr) Match(a, b reflect.Value) bool {
	return diff.AreType(a, b, reflect.TypeOf(netip.Addr{}))
}

func (differ NetIPAddr) Diff(_ diff.DiffType, _ diff.DiffFunc, cl *diff.Changelog, path []string, a, b reflect.Value, _ interface{}) error {
	if a.Kind() == reflect.Invalid {
		cl.Add(diff.CREATE, path, nil, b.Interface())
		return nil
	}

	if b.Kind() == reflect.Invalid {
		cl.Add(diff.DELETE, path, a.Interface(), nil)
		return nil
	}

	fromAddr, ok1 := a.Interface().(netip.Addr)
	toAddr, ok2 := b.Interface().(netip.Addr)
	if !ok1 || !ok2 {
		return fmt.Errorf("invalid type for netip.Addr")
	}

	if fromAddr.String() != toAddr.String() {
		cl.Add(diff.UPDATE, path, fromAddr.String(), toAddr.String())
	}

	return nil
}

func (differ NetIPAddr) InsertParentDiffer(dfunc func(path []string, a, b reflect.Value, p interface{}) error) {
	differ.DiffFunc = dfunc //nolint
}

// NetIPPrefix is a custom differ for netip.Prefix
type NetIPPrefix struct {
	DiffFunc func(path []string, a, b reflect.Value, p interface{}) error
}

func (differ NetIPPrefix) Match(a, b reflect.Value) bool {
	return diff.AreType(a, b, reflect.TypeOf(netip.Prefix{}))
}

func (differ NetIPPrefix) Diff(_ diff.DiffType, _ diff.DiffFunc, cl *diff.Changelog, path []string, a, b reflect.Value, _ interface{}) error {
	if a.Kind() == reflect.Invalid {
		cl.Add(diff.CREATE, path, nil, b.Interface())
		return nil
	}
	if b.Kind() == reflect.Invalid {
		cl.Add(diff.DELETE, path, a.Interface(), nil)
		return nil
	}

	fromPrefix, ok1 := a.Interface().(netip.Prefix)
	toPrefix, ok2 := b.Interface().(netip.Prefix)
	if !ok1 || !ok2 {
		return fmt.Errorf("invalid type for netip.Addr")
	}

	if fromPrefix.String() != toPrefix.String() {
		cl.Add(diff.UPDATE, path, fromPrefix.String(), toPrefix.String())
	}

	return nil
}

func (differ NetIPPrefix) InsertParentDiffer(dfunc func(path []string, a, b reflect.Value, p interface{}) error) {
	differ.DiffFunc = dfunc //nolint
}
