// Package harness writes the user config of coding agents ("harnesses") so
// they send model requests to the Agent Networks endpoint. Each harness is a
// declarative Definition; one engine plans, applies and reverts all of them.
package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Format is the encoding of a config file.
type Format string

const (
	// FormatJSON is strict JSON, without comments or trailing commas.
	FormatJSON Format = "json"
	// FormatTOML is TOML, edited line by line so comments and layout survive.
	FormatTOML Format = "toml"
)

// Var is a placeholder a Key value may reference as {name}.
type Var string

const (
	// VarEndpoint is the Agent Networks base URL, without a trailing slash.
	VarEndpoint Var = "endpoint"
	// VarModel is the chosen model. Keys that reference it are skipped when
	// no model was chosen, so the harness keeps picking its own.
	VarModel Var = "model"
	// VarVertexProject is the GCP project id Vertex AI requests carry.
	VarVertexProject Var = "vertex_project"
)

// File is one config file of a harness.
type File struct {
	// DirEnv names the environment variable that replaces the directory.
	DirEnv string
	// DirEnvSuffix is joined to DirEnv's value, for a variable that names a
	// parent directory such as XDG_CONFIG_HOME.
	DirEnvSuffix string
	// Dir is the directory relative to the home directory, slash-separated.
	Dir string
	// DirByOS replaces Dir on the given GOOS.
	DirByOS map[string]string
	Name    string
	Format  Format
}

// Key is one setting a variant writes.
type Key struct {
	// File indexes Definition.Files.
	File int
	Path []string
	// Value is a template with {var} placeholders.
	Value string
	// JSON marks Value as a JSON template, for a value that is not a string.
	// Placeholders are substituted JSON-escaped.
	JSON bool
}

// Variant is the set of keys that points a harness at one kind of provider.
type Variant struct {
	Keys []Key
	// DefaultModel is used when the provider lists no models and none was
	// asked for. Empty leaves the model to the harness.
	DefaultModel string
}

// Definition describes how to point one harness at the endpoint.
type Definition struct {
	ID   string
	Name string
	// CheckedVersion is the harness version the keys were verified against.
	CheckedVersion string
	Files          []File
	// Variants is keyed by provider catalog id, falling back to API flavor.
	Variants map[string]Variant
	// Notice is shown after a write.
	Notice string
	// CAEnv names the variable the harness reads a private CA from.
	CAEnv string
}

// Env is the host the paths resolve on, injected so tests can resolve
// another OS's paths.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
	// RecordPath is where the ownership record is kept.
	RecordPath string
}

// Setting is a rendered key: the file it lives in and the value to write.
type Setting struct {
	File   string
	Format Format
	Path   []string
	Value  any
}

// MissingVarError reports a placeholder the variant needs but was not given.
type MissingVarError struct{ Var Var }

func (e *MissingVarError) Error() string {
	return fmt.Sprintf("missing value for %s", e.Var)
}

var definitions = []*Definition{claudeCode, codex, openCode, pi}

// All returns the supported harnesses.
func All() []*Definition {
	return definitions
}

// Lookup returns the harness with the given id.
func Lookup(id string) (*Definition, error) {
	for _, d := range definitions {
		if d.ID == id {
			return d, nil
		}
	}
	ids := make([]string, 0, len(definitions))
	for _, d := range definitions {
		ids = append(ids, d.ID)
	}
	return nil, fmt.Errorf("unknown harness %q, supported: %s", id, strings.Join(ids, ", "))
}

// Variant returns the keys for a provider, by catalog id first and API
// flavor second.
func (d *Definition) Variant(catalogID, flavor string) (Variant, bool) {
	if v, ok := d.Variants[catalogID]; ok {
		return v, true
	}
	if flavor == "" {
		return Variant{}, false
	}
	v, ok := d.Variants[flavor]
	return v, ok
}

// Path returns the file's location on env.
func (f File) Path(env Env) string {
	sep := "/"
	if env.GOOS == "windows" {
		sep = `\`
	}
	dir := ""
	if f.DirEnv != "" && env.Getenv != nil {
		dir = env.Getenv(f.DirEnv)
	}
	if dir != "" && f.DirEnvSuffix != "" {
		dir = strings.TrimRight(dir, `/\`) + sep + f.DirEnvSuffix
	}
	if dir == "" {
		rel := f.Dir
		if d, ok := f.DirByOS[env.GOOS]; ok {
			rel = d
		}
		dir = strings.TrimRight(env.Home, `/\`) + sep + strings.ReplaceAll(path.Clean(rel), "/", sep)
	}
	return strings.TrimRight(dir, `/\`) + sep + f.Name
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// Render resolves a variant's keys against vars. A key referencing an empty
// VarModel is dropped; any other empty placeholder is a MissingVarError.
func (d *Definition) Render(v Variant, vars map[Var]string, env Env) ([]Setting, error) {
	var out []Setting
	for _, k := range v.Keys {
		value, err := renderValue(k, vars)
		var missing *MissingVarError
		if errors.As(err, &missing) && missing.Var == VarModel {
			continue
		}
		if err != nil {
			return nil, err
		}
		f := d.Files[k.File]
		out = append(out, Setting{File: f.Path(env), Format: f.Format, Path: k.Path, Value: value})
	}
	return out, nil
}

func renderValue(k Key, vars map[Var]string) (any, error) {
	if !k.JSON {
		return expand(k.Value, vars, func(s string) string { return s })
	}
	raw, err := expand(k.Value, vars, jsonEscape)
	if err != nil {
		return nil, err
	}
	var v any
	if err := decodeValue([]byte(raw), &v); err != nil {
		return nil, fmt.Errorf("render %s: %w", PathString(k.Path), err)
	}
	return v, nil
}

func expand(tmpl string, vars map[Var]string, escape func(string) string) (string, error) {
	var err error
	value := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := Var(m[1 : len(m)-1])
		val := vars[name]
		if val == "" && err == nil {
			err = &MissingVarError{Var: name}
		}
		return escape(val)
	})
	return value, err
}

// jsonEscape returns s as the inside of a JSON string literal.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// Fragments renders settings as the per-file snippet a user can paste.
func Fragments(settings []Setting) (map[string]string, error) {
	docs := map[string]map[string]any{}
	formats := map[string]Format{}
	for _, s := range settings {
		if docs[s.File] == nil {
			docs[s.File] = map[string]any{}
			formats[s.File] = s.Format
		}
		if err := setPath(docs[s.File], s.Path, s.Value); err != nil {
			return nil, err
		}
	}
	out := make(map[string]string, len(docs))
	for file, doc := range docs {
		data, err := codecFor(formats[file]).encode(nil, doc)
		if err != nil {
			return nil, err
		}
		out[file] = string(data)
	}
	return out, nil
}

// SortedFiles returns the keys of a per-file map in order.
func SortedFiles[T any](m map[string]T) []string {
	files := make([]string, 0, len(m))
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}
