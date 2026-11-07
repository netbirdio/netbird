//go:build !windows

package instance

// LoadRecord reads the record of a named installation. Only Windows has named
// installations.
func LoadRecord(Name) (Record, error) {
	return Record{}, ErrNoRecord
}

// ListRecords returns the records of every named installation: none outside
// Windows.
func ListRecords() ([]Record, error) {
	return nil, nil
}
