package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

// Record lists every key NetBird wrote, so undo touches only those.
type Record struct {
	Harnesses map[string]*Entry `json:"harnesses"`
}

// Entry is what NetBird wrote for one harness, by file path.
type Entry struct {
	Files map[string]*FileRecord `json:"files"`
}

// FileRecord is what NetBird wrote to one file.
type FileRecord struct {
	Format  Format     `json:"format"`
	Backups []string   `json:"backups,omitempty"`
	Keys    []OwnedKey `json:"keys"`
}

// OwnedKey is a key NetBird wrote and the value it replaced.
type OwnedKey struct {
	Path     []string        `json:"path"`
	Written  json.RawMessage `json:"written"`
	HadPrior bool            `json:"had_prior"`
	Prior    json.RawMessage `json:"prior,omitempty"`
}

// LoadRecord reads the record at path; a missing file is an empty record.
func LoadRecord(path string) (*Record, error) {
	rec := &Record{Harnesses: map[string]*Entry{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, rec); err != nil {
		return nil, err
	}
	if rec.Harnesses == nil {
		rec.Harnesses = map[string]*Entry{}
	}
	return rec, rec.compact()
}

// compact undoes the indentation Save gives recorded values, so they compare
// byte for byte with their canonical form.
func (r *Record) compact() error {
	for _, e := range r.Harnesses {
		for _, fr := range e.Files {
			for i := range fr.Keys {
				k := &fr.Keys[i]
				for _, raw := range []*json.RawMessage{&k.Written, &k.Prior} {
					if len(*raw) == 0 {
						continue
					}
					var buf bytes.Buffer
					if err := json.Compact(&buf, *raw); err != nil {
						return err
					}
					*raw = buf.Bytes()
				}
			}
		}
	}
	return nil
}

// Save writes the record to path as 0600.
func (r *Record) Save(path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes(), 0o600)
}
