package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Action is what a Change does to a key.
type Action string

const (
	// ActionSet writes the NetBird value.
	ActionSet Action = "set"
	// ActionRestore puts back the value the key held before NetBird wrote it,
	// or removes the key when it had none.
	ActionRestore Action = "restore"
	// ActionKeep leaves a key NetBird wrote but the user has since changed.
	ActionKeep Action = "keep"
)

// Change is one key a Plan touches.
type Change struct {
	File   string
	Path   []string
	Action Action
	// Before is the current value, nil when the key is absent.
	Before json.RawMessage
	// After is the value written, nil when the key is removed.
	After json.RawMessage
	// Conflict marks a set over a value NetBird did not write.
	Conflict bool
}

// Plan is the set of changes that brings the files to the wanted settings.
type Plan struct {
	harness string
	Changes []Change
	files   map[string]*fileState
}

type fileState struct {
	format Format
	// target is the path written, with symlinks resolved.
	target string
	exists bool
	mode   fs.FileMode
	raw    []byte
	doc    map[string]any
	owned  []OwnedKey
	dirty  bool
}

// ErrConflict is returned by Plan when a key holds a value NetBird did not
// write; the Plan is still returned so the caller can show it.
var ErrConflict = errors.New("settings hold values NetBird did not write")

// UnparseableError reports a config file the engine cannot round-trip, such
// as JSON with comments. Printing the settings still works.
type UnparseableError struct {
	File string
	Err  error
}

func (e *UnparseableError) Error() string {
	return fmt.Sprintf("cannot parse %s: %v", e.File, e.Err)
}

func (e *UnparseableError) Unwrap() error { return e.Err }

// Pending reports whether applying the plan writes anything.
func (p *Plan) Pending() bool {
	for _, f := range p.files {
		if f.dirty {
			return true
		}
	}
	return false
}

// NewPlan compares the wanted settings of a harness with the files and the
// ownership record. Keys NetBird wrote earlier that are no longer wanted are
// restored. With no settings, it plans an undo.
func NewPlan(id string, settings []Setting, rec *Record, force bool) (*Plan, error) {
	p := &Plan{harness: id, files: map[string]*fileState{}}
	owned := rec.Harnesses[id]

	byFile := map[string][]Setting{}
	for _, s := range settings {
		byFile[s.File] = append(byFile[s.File], s)
	}
	formats := map[string]Format{}
	for _, s := range settings {
		formats[s.File] = s.Format
	}
	if owned != nil {
		for file, fr := range owned.Files {
			if _, ok := formats[file]; !ok {
				formats[file] = fr.Format
			}
		}
	}

	conflict := false
	for _, file := range SortedFiles(formats) {
		var fr *FileRecord
		if owned != nil {
			fr = owned.Files[file]
		}
		st, err := loadFile(file, formats[file])
		if err != nil {
			return nil, err
		}
		p.files[file] = st
		c, err := p.planFile(file, st, byFile[file], fr, force)
		if err != nil {
			return nil, err
		}
		conflict = conflict || c
	}
	if conflict && !force {
		return p, ErrConflict
	}
	return p, nil
}

func (p *Plan) planFile(file string, st *fileState, want []Setting, fr *FileRecord, force bool) (bool, error) {
	ownedByPath := map[string]OwnedKey{}
	if fr != nil {
		for _, k := range fr.Keys {
			ownedByPath[pathKey(k.Path)] = k
		}
	}

	conflict := false
	wanted := map[string]bool{}
	for _, s := range want {
		wanted[pathKey(s.Path)] = true
		after, err := canonical(s.Value)
		if err != nil {
			return false, err
		}
		cur, present, err := getPath(st.doc, s.Path)
		if err != nil {
			return false, fmt.Errorf("%s: %w", file, err)
		}
		own, isOwned := ownedByPath[pathKey(s.Path)]
		if present && bytes.Equal(cur, after) {
			if isOwned {
				st.owned = append(st.owned, own)
			}
			continue
		}
		ours := isOwned && present && bytes.Equal(cur, own.Written)
		c := Change{File: file, Path: s.Path, Action: ActionSet, After: after, Conflict: present && !ours}
		if present {
			c.Before = cur
		}
		conflict = conflict || c.Conflict
		p.Changes = append(p.Changes, c)

		// The prior value is what the user had before NetBird; a value the
		// user set over ours replaces it.
		next := OwnedKey{Path: s.Path, Written: after, HadPrior: present, Prior: cur}
		if isOwned && (ours || !present) {
			next.HadPrior, next.Prior = own.HadPrior, own.Prior
		}
		st.owned = append(st.owned, next)
		if err := setPath(st.doc, s.Path, s.Value); err != nil {
			return false, fmt.Errorf("%s: %w", file, err)
		}
		st.dirty = true
	}

	if fr == nil {
		return conflict, nil
	}
	for _, own := range fr.Keys {
		if wanted[pathKey(own.Path)] {
			continue
		}
		if err := p.release(file, st, own); err != nil {
			return false, err
		}
	}
	return conflict, nil
}

// release plans putting back a key NetBird no longer wants, unless the user
// changed it since.
func (p *Plan) release(file string, st *fileState, own OwnedKey) error {
	cur, present, err := getPath(st.doc, own.Path)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	c := Change{File: file, Path: own.Path, Action: ActionKeep}
	if present {
		c.Before = cur
	}
	if !present || !bytes.Equal(cur, own.Written) {
		p.Changes = append(p.Changes, c)
		return nil
	}

	c.Action = ActionRestore
	if own.HadPrior {
		c.After = own.Prior
		var v any
		if err := decodeValue(own.Prior, &v); err != nil {
			return fmt.Errorf("decode recorded value: %w", err)
		}
		if err := setPath(st.doc, own.Path, v); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	} else {
		deletePath(st.doc, own.Path)
	}
	p.Changes = append(p.Changes, c)
	st.dirty = true
	return nil
}

// Apply writes the planned files, each after a backup, updates the record
// and returns the backups made. A plan that changes neither the files nor
// the record writes nothing.
func (p *Plan) Apply(rec *Record, recordPath string, now time.Time) ([]string, error) {
	if !p.Pending() && !p.releasesKeys() {
		return nil, nil
	}
	hr := rec.Harnesses[p.harness]
	if hr == nil {
		hr = &Entry{}
	}
	if hr.Files == nil {
		hr.Files = map[string]*FileRecord{}
	}

	var backups []string
	for _, file := range SortedFiles(p.files) {
		st := p.files[file]
		fr := hr.Files[file]
		if fr == nil {
			fr = &FileRecord{Format: st.format}
		}
		if st.dirty {
			backup, err := st.write(now)
			if err != nil {
				return backups, fmt.Errorf("write %s: %w", file, err)
			}
			if backup != "" {
				fr.Backups = append(fr.Backups, backup)
				backups = append(backups, backup)
			}
		}
		fr.Keys = st.owned
		if len(fr.Keys) == 0 {
			delete(hr.Files, file)
			continue
		}
		hr.Files[file] = fr
	}

	if rec.Harnesses == nil {
		rec.Harnesses = map[string]*Entry{}
	}
	rec.Harnesses[p.harness] = hr
	if len(hr.Files) == 0 {
		delete(rec.Harnesses, p.harness)
	}
	return backups, rec.Save(recordPath)
}

// releasesKeys reports whether the plan gives up keys the user changed, which
// only the record reflects.
func (p *Plan) releasesKeys() bool {
	for _, c := range p.Changes {
		if c.Action == ActionKeep {
			return true
		}
	}
	return false
}

func (st *fileState) write(now time.Time) (string, error) {
	data, err := codecFor(st.format).encode(st.raw, st.doc)
	if err != nil {
		return "", err
	}
	backup := ""
	if st.exists {
		if backup, err = writeBackup(st.target, st.mode, now); err != nil {
			return "", fmt.Errorf("back up: %w", err)
		}
	}
	return backup, writeAtomic(st.target, data, st.mode)
}

func loadFile(file string, format Format) (*fileState, error) {
	st := &fileState{format: format, target: file, mode: 0o600, doc: map[string]any{}}
	if resolved, err := filepath.EvalSymlinks(file); err == nil {
		st.target = resolved
	}
	info, err := os.Stat(st.target)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(st.target)
	if err != nil {
		return nil, err
	}
	doc, err := codecFor(format).decode(data)
	if err != nil {
		return nil, &UnparseableError{File: file, Err: err}
	}
	st.exists, st.mode, st.raw, st.doc = true, info.Mode().Perm(), data, doc
	return st, nil
}

// Status reports whether NetBird's settings for a harness are in place:
// "configured", "configured, edited since" or "not configured".
func Status(id string, rec *Record) string {
	hr := rec.Harnesses[id]
	if hr == nil || len(hr.Files) == 0 {
		return "not configured"
	}
	for file, fr := range hr.Files {
		st, err := loadFile(file, fr.Format)
		if err != nil {
			return "configured, " + err.Error()
		}
		for _, k := range fr.Keys {
			cur, present, err := getPath(st.doc, k.Path)
			if err != nil || !present || !bytes.Equal(cur, k.Written) {
				return "configured, edited since"
			}
		}
	}
	return "configured"
}

// PathString renders a key path for display.
func PathString(p []string) string {
	return strings.Join(p, ".")
}

func pathKey(p []string) string {
	return strings.Join(p, "\x00")
}

// writeBackup copies file to <file>.netbird-backup-<UTC timestamp>, keeping
// its mode, and never overwrites an earlier backup.
func writeBackup(file string, mode fs.FileMode, now time.Time) (string, error) {
	src, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer src.Close()

	base := file + ".netbird-backup-" + now.UTC().Format("20060102T150405Z")
	name := base
	var dst *os.File
	for i := 1; ; i++ {
		dst, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	if err != nil {
		return "", err
	}
	if err := copyAndClose(dst, src, mode); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func copyAndClose(dst *os.File, src io.Reader, mode fs.FileMode) error {
	_, err := io.Copy(dst, src)
	if err == nil {
		// The umask applies at create time; set the mode it should have.
		err = dst.Chmod(mode)
	}
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	return err
}

// writeAtomic replaces file with data through a synced temp file in the same
// directory, creating a missing directory as 0700.
func writeAtomic(file string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(file)+".tmp-*")
	if err != nil {
		return err
	}
	if err := copyAndClose(tmp, bytes.NewReader(data), mode); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}
