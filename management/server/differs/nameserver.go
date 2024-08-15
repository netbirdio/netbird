package differs

import (
	"fmt"
	"reflect"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/r3labs/diff"
)

type NameServerComparator struct{}

func NewNameServerComparator() *NameServerComparator {
	return &NameServerComparator{}
}

func (d *NameServerComparator) Match(a, b reflect.Value) bool {
	return diff.AreType(a, b, reflect.TypeOf(nbdns.NameServer{})) ||
		diff.AreType(a, b, reflect.TypeOf([]nbdns.NameServer{}))
}

func (d *NameServerComparator) Diff(cl *diff.Changelog, path []string, a, b reflect.Value) error {
	if a.Kind() == reflect.Invalid {
		cl.Add(diff.CREATE, path, nil, b.Interface())
		return nil
	}
	if b.Kind() == reflect.Invalid {
		cl.Add(diff.DELETE, path, a.Interface(), nil)
		return nil
	}

	if a.Kind() == reflect.Slice && b.Kind() == reflect.Slice {
		if a.Len() != b.Len() {
			cl.Add(diff.UPDATE, append(path, "length"), a.Len(), b.Len())
			return nil
		}

		for i := 0; i < min(a.Len(), b.Len()); i++ {
			err := d.Diff(cl, append(path, fmt.Sprintf("[%d]", i)), a.Index(i), b.Index(i))
			if err != nil {
				return err
			}
		}
		return nil
	}

	ns1, ok1 := a.Interface().(nbdns.NameServer)
	ns2, ok2 := b.Interface().(nbdns.NameServer)
	if !ok1 || !ok2 {
		return fmt.Errorf("invalid type for NameServer")
	}

	if ns1.IP.String() != ns2.IP.String() {
		cl.Add(diff.UPDATE, append(path, "IP"), ns1.IP.String(), ns2.IP.String())
	}
	if ns1.NSType != ns2.NSType {
		cl.Add(diff.UPDATE, append(path, "NSType"), ns1.NSType, ns2.NSType)
	}
	if ns1.Port != ns2.Port {
		cl.Add(diff.UPDATE, append(path, "Port"), ns1.Port, ns2.Port)
	}

	return nil
}