// Package sqltypes holds the column types the generated queries map JSON text
// columns to.
package sqltypes

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Strings is a string slice stored as a JSON array in a text column, the
// encoding gorm's json serializer used for the same columns.
type Strings []string

// Scan decodes the JSON array; NULL and JSON null become an empty slice.
func (s *Strings) Scan(value any) error {
	if value == nil {
		*s = Strings{}
		return nil
	}
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("scan Strings from %T", value)
	}
	if len(raw) == 0 {
		*s = Strings{}
		return nil
	}
	var decoded []string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode Strings: %w", err)
	}
	if decoded == nil {
		decoded = []string{}
	}
	*s = decoded
	return nil
}

// Value encodes the slice as a JSON array; a nil slice is stored as an empty array.
func (s Strings) Value() (driver.Value, error) {
	if s == nil {
		s = Strings{}
	}
	encoded, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("encode Strings: %w", err)
	}
	return string(encoded), nil
}
