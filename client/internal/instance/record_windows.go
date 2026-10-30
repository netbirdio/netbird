//go:build windows

package instance

import (
	"errors"
	"fmt"
	"sort"

	"golang.org/x/sys/windows/registry"
)

const recordAccess = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY

// LoadRecord reads the record of a named installation.
func LoadRecord(name Name) (Record, error) {
	if name == DefaultName {
		return Record{}, ErrNoRecord
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, recordsKey+`\`+string(name), recordAccess)
	if errors.Is(err, registry.ErrNotExist) {
		return Record{}, ErrNoRecord
	}
	if err != nil {
		return Record{}, fmt.Errorf("open installation record %s: %w", name, err)
	}
	defer func() { _ = k.Close() }()

	rec := Record{Name: name}
	for value, dst := range map[string]*string{
		"Label":      &rec.Label,
		"Color":      &rec.Color,
		"Role":       &rec.Role,
		"InstallDir": &rec.InstallDir,
		"Version":    &rec.Version,
	} {
		v, _, err := k.GetStringValue(value)
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return Record{}, fmt.Errorf("read %s of installation record %s: %w", value, name, err)
		}
		*dst = v
	}
	return rec, nil
}

// ListRecords returns the records of every named installation with a valid
// name, sorted by name. Subkeys that are not valid names are skipped.
func ListRecords() ([]Record, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, recordsKey, recordAccess)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open installation records: %w", err)
	}
	defer func() { _ = k.Close() }()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("list installation records: %w", err)
	}
	sort.Strings(names)

	var recs []Record
	for _, n := range names {
		name, _, err := ParseName(n)
		if err != nil || name == DefaultName || string(name) != n {
			continue
		}
		rec, err := LoadRecord(name)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}
