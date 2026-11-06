package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The TOML codec edits a file line by line rather than re-encoding it, so
// comments, ordering and values it does not understand survive. It parses
// strings, booleans and decimal numbers into values; arrays, inline tables,
// multi-line strings, dates and the like are kept as their raw text.

// tomlRaw is a value kept as written.
type tomlRaw string

// tomlSpan locates a key's value: it starts at col on line and ends before
// endCol on endLine.
type tomlSpan struct {
	line, col, endLine, endCol int
}

// tomlSection is a [table] or [[array]] header and the last line of its
// key/values.
type tomlSection struct {
	path    []string
	array   bool
	header  int
	lastKey int
}

type tomlFile struct {
	lines    []string
	crlf     bool
	doc      map[string]any
	spans    map[string]tomlSpan
	sections []tomlSection
	// topEnd is the last line of the top-level key/values, -1 when none.
	topEnd int
}

var (
	tomlBareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// tomlNumber is the TOML number syntax JSON shares; others stay raw.
	tomlNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

func decodeTOMLDoc(data []byte) (map[string]any, error) {
	f, err := parseTOML(data)
	if err != nil {
		return nil, err
	}
	return f.doc, nil
}

func parseTOML(data []byte) (*tomlFile, error) {
	text := string(data)
	f := &tomlFile{
		crlf:   strings.Contains(text, "\r\n"),
		doc:    map[string]any{},
		spans:  map[string]tomlSpan{},
		topEnd: -1,
	}
	if text != "" {
		f.lines = strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		if f.lines[len(f.lines)-1] == "" {
			f.lines = f.lines[:len(f.lines)-1]
		}
	}

	var table []string
	inArray := false
	for i := 0; i < len(f.lines); i++ {
		trimmed := strings.TrimSpace(f.lines[i])
		var err error
		switch {
		case trimmed == "" || trimmed[0] == '#':
			continue
		case strings.HasPrefix(trimmed, "[["):
			table, err = f.arrayHeader(i, trimmed)
			inArray = true
		case trimmed[0] == '[':
			table, err = f.tableHeader(i, trimmed)
			inArray = false
		default:
			i, err = f.keyValue(i, table, inArray)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return f, nil
}

// arrayHeader records an array of tables as one raw value; NetBird never
// writes inside one.
func (f *tomlFile) arrayHeader(i int, line string) ([]string, error) {
	path, rest, err := parseTOMLKey(line[2:])
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(rest, "]]") || !tomlBlank(rest[2:]) {
		return nil, errors.New("malformed array of tables header")
	}
	if _, present, _ := getPath(f.doc, path); !present {
		if err := setPath(f.doc, path, tomlRaw("[[array of tables]]")); err != nil {
			return nil, err
		}
	}
	f.sections = append(f.sections, tomlSection{path: path, array: true, header: i, lastKey: i})
	return path, nil
}

func (f *tomlFile) tableHeader(i int, line string) ([]string, error) {
	path, rest, err := parseTOMLKey(line[1:])
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(rest, "]") || !tomlBlank(rest[1:]) {
		return nil, errors.New("malformed table header")
	}
	if err := ensureTable(f.doc, path); err != nil {
		return nil, err
	}
	f.sections = append(f.sections, tomlSection{path: path, header: i, lastKey: i})
	return path, nil
}

// keyValue parses the key/value starting on line i and returns the line it
// ends on.
func (f *tomlFile) keyValue(i int, table []string, inArray bool) (int, error) {
	line := f.lines[i]
	start := len(line) - len(strings.TrimLeft(line, " \t"))
	key, rest, err := parseTOMLKey(line[start:])
	if err != nil {
		return i, err
	}
	if !strings.HasPrefix(rest, "=") {
		return i, errors.New("expected =")
	}
	col := len(line) - len(strings.TrimLeft(rest[1:], " \t"))
	value, end, endCol, err := f.scanValue(i, col)
	if err != nil {
		return i, err
	}
	if !tomlBlank(f.lines[end][endCol:]) {
		return i, errors.New("unexpected text after value")
	}

	if len(f.sections) == 0 {
		f.topEnd = end
	} else {
		f.sections[len(f.sections)-1].lastKey = end
	}
	if inArray {
		return end, nil
	}
	path := append(append([]string{}, table...), key...)
	if err := setPath(f.doc, path, value); err != nil {
		return i, err
	}
	f.spans[pathKey(path)] = tomlSpan{line: i, col: col, endLine: end, endCol: endCol}
	return end, nil
}

// scanValue reads the value at lines[i][col:], which may span lines.
func (f *tomlFile) scanValue(i, col int) (any, int, int, error) {
	line := f.lines[i]
	rest := line[col:]
	switch {
	case strings.HasPrefix(rest, `"""`), strings.HasPrefix(rest, `'''`):
		end, endCol, err := f.scanTo(i, col+3, rest[:3])
		if err != nil {
			return nil, 0, 0, err
		}
		return f.raw(i, col, end, endCol), end, endCol, nil
	case strings.HasPrefix(rest, `"`):
		n := basicStringLen(rest)
		if n < 0 {
			return nil, 0, 0, errors.New("unterminated string")
		}
		s, err := strconv.Unquote(rest[:n])
		if err != nil {
			return nil, 0, 0, fmt.Errorf("string: %w", err)
		}
		return s, i, col + n, nil
	case strings.HasPrefix(rest, `'`):
		n := strings.IndexByte(rest[1:], '\'')
		if n < 0 {
			return nil, 0, 0, errors.New("unterminated string")
		}
		return rest[1 : n+1], i, col + n + 2, nil
	case strings.HasPrefix(rest, "["), strings.HasPrefix(rest, "{"):
		end, endCol, err := f.scanBrackets(i, col)
		if err != nil {
			return nil, 0, 0, err
		}
		return f.raw(i, col, end, endCol), end, endCol, nil
	}

	tok := rest
	if n := strings.IndexByte(tok, '#'); n >= 0 {
		tok = tok[:n]
	}
	tok = strings.TrimRight(tok, " \t")
	if tok == "" {
		return nil, 0, 0, errors.New("missing value")
	}
	return tomlScalar(tok), i, col + len(tok), nil
}

func tomlScalar(tok string) any {
	switch tok {
	case "true":
		return true
	case "false":
		return false
	}
	if tomlNumber.MatchString(tok) {
		return json.Number(tok)
	}
	return tomlRaw(tok)
}

// scanTo finds the end of a multi-line string closed by delim.
func (f *tomlFile) scanTo(i, col int, delim string) (int, int, error) {
	for ; i < len(f.lines); i, col = i+1, 0 {
		line := f.lines[i]
		for j := col; j <= len(line)-3; j++ {
			if delim == `"""` && line[j] == '\\' {
				j++
				continue
			}
			if line[j:j+3] == delim {
				// Up to two more quotes may close the string.
				end := j + 3
				for end < len(line) && line[end] == delim[0] && end < j+5 {
					end++
				}
				return i, end, nil
			}
		}
	}
	return 0, 0, errors.New("unterminated multi-line string")
}

// scanBrackets finds the end of an array or inline table, skipping strings
// and comments inside it.
func (f *tomlFile) scanBrackets(i, col int) (int, int, error) {
	depth := 0
	for ; i < len(f.lines); i, col = i+1, 0 {
		line := f.lines[i]
		for j := col; j < len(line); j++ {
			switch c := line[j]; {
			case c == '#':
				j = len(line)
			case strings.HasPrefix(line[j:], `"""`), strings.HasPrefix(line[j:], `'''`):
				end, endCol, err := f.scanTo(i, j+3, line[j:j+3])
				if err != nil {
					return 0, 0, err
				}
				i, line, j = end, f.lines[end], endCol-1
			case c == '"':
				n := basicStringLen(line[j:])
				if n < 0 {
					return 0, 0, errors.New("unterminated string")
				}
				j += n - 1
			case c == '\'':
				n := strings.IndexByte(line[j+1:], '\'')
				if n < 0 {
					return 0, 0, errors.New("unterminated string")
				}
				j += n + 1
			case c == '[' || c == '{':
				depth++
			case c == ']' || c == '}':
				depth--
				if depth == 0 {
					return i, j + 1, nil
				}
			}
		}
	}
	return 0, 0, errors.New("unterminated array or inline table")
}

func (f *tomlFile) raw(i, col, end, endCol int) tomlRaw {
	if i == end {
		return tomlRaw(f.lines[i][col:endCol])
	}
	parts := []string{f.lines[i][col:]}
	parts = append(parts, f.lines[i+1:end]...)
	parts = append(parts, f.lines[end][:endCol])
	return tomlRaw(strings.Join(parts, "\n"))
}

// basicStringLen returns the length of the "..." string s starts with, or -1.
func basicStringLen(s string) int {
	for j := 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return -1
}

// parseTOMLKey reads a dotted key of bare and quoted parts and returns the
// text after it, trimmed.
func parseTOMLKey(s string) ([]string, string, error) {
	var key []string
	for {
		s = strings.TrimLeft(s, " \t")
		var part string
		switch {
		case strings.HasPrefix(s, `"`):
			n := basicStringLen(s)
			if n < 0 {
				return nil, "", errors.New("unterminated quoted key")
			}
			var err error
			if part, err = strconv.Unquote(s[:n]); err != nil {
				return nil, "", fmt.Errorf("quoted key: %w", err)
			}
			s = s[n:]
		case strings.HasPrefix(s, `'`):
			n := strings.IndexByte(s[1:], '\'')
			if n < 0 {
				return nil, "", errors.New("unterminated quoted key")
			}
			part, s = s[1:n+1], s[n+2:]
		default:
			n := strings.IndexFunc(s, func(r rune) bool {
				return !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
			})
			if n < 0 {
				n = len(s)
			}
			if n == 0 {
				return nil, "", errors.New("expected a key")
			}
			part, s = s[:n], s[n:]
		}
		key = append(key, part)
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ".") {
			return key, s, nil
		}
		s = s[1:]
	}
}

func tomlBlank(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s[0] == '#'
}

func ensureTable(doc map[string]any, path []string) error {
	cur := doc
	for i, k := range path {
		next, ok := cur[k]
		if !ok {
			m := map[string]any{}
			cur[k] = m
			cur = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not a table", PathString(path[:i+1]))
		}
		cur = m
	}
	return nil
}

// encodeTOMLDoc edits orig so it holds doc: changed values are replaced in
// place, removed keys deleted, new top-level keys added after the existing
// ones and new keys of a table added to its section, or to a new section at
// the end of the file.
func encodeTOMLDoc(orig []byte, doc map[string]any) ([]byte, error) {
	f, err := parseTOML(orig)
	if err != nil {
		return nil, err
	}
	e := newTOMLEdit(f)
	oldLeaves, newLeaves := tomlLeaves(f.doc, nil), tomlLeaves(doc, nil)
	for _, k := range sortedLeafKeys(oldLeaves) {
		if _, keep := newLeaves[k]; !keep {
			e.remove(f.spans[k])
		}
	}
	for _, k := range sortedLeafKeys(newLeaves) {
		leaf := newLeaves[k]
		enc, err := encodeTOMLValue(leaf.value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", PathString(leaf.path), err)
		}
		old, ok := oldLeaves[k]
		switch {
		case !ok:
			err = e.add(leaf.path, enc)
		case !sameJSON(old.value, leaf.value):
			e.replace(f.spans[k], enc)
		}
		if err != nil {
			return nil, err
		}
	}
	e.dropRemovedSections(doc)
	return e.render(), nil
}

// tomlEdit collects line edits against a parsed file. out[i] replaces line
// i and before[i] goes ahead of it; before[len(lines)] is the end of file.
type tomlEdit struct {
	f          *tomlFile
	out        [][]string
	before     map[int][]string
	newTables  map[string][]string
	tableOrder [][]string
}

func newTOMLEdit(f *tomlFile) *tomlEdit {
	e := &tomlEdit{f: f, out: make([][]string, len(f.lines)), before: map[int][]string{}, newTables: map[string][]string{}}
	for i, l := range f.lines {
		e.out[i] = []string{l}
	}
	return e
}

func (e *tomlEdit) remove(sp tomlSpan) {
	for i := sp.line; i <= sp.endLine; i++ {
		e.out[i] = nil
	}
}

func (e *tomlEdit) replace(sp tomlSpan, enc string) {
	lines := e.f.lines
	e.remove(sp)
	e.out[sp.line] = []string{lines[sp.line][:sp.col] + enc + lines[sp.endLine][sp.endCol:]}
}

func (e *tomlEdit) add(path []string, enc string) error {
	parent := path[:len(path)-1]
	line := encodeTOMLKey(path[len(path)-1:]) + " = " + enc
	if len(parent) == 0 {
		e.before[e.f.topEnd+1] = append(e.before[e.f.topEnd+1], line)
		return nil
	}
	if s := e.f.section(parent); s != nil {
		e.before[s.lastKey+1] = append(e.before[s.lastKey+1], line)
		return nil
	}
	if dottedTable(e.f.doc, parent) {
		return fmt.Errorf("cannot add to %s: it is defined with dotted keys", PathString(parent))
	}
	pk := pathKey(parent)
	if _, ok := e.newTables[pk]; !ok {
		e.tableOrder = append(e.tableOrder, parent)
	}
	e.newTables[pk] = append(e.newTables[pk], line)
	return nil
}

// dropRemovedSections deletes the header of a table doc no longer has, with
// the blank line that separated it.
func (e *tomlEdit) dropRemovedSections(doc map[string]any) {
	for _, s := range e.f.sections {
		if s.array {
			continue
		}
		if _, present, _ := getPath(doc, s.path); present {
			continue
		}
		e.out[s.header] = nil
		if s.header > 0 && strings.TrimSpace(e.f.lines[s.header-1]) == "" {
			e.out[s.header-1] = nil
		}
	}
}

func (e *tomlEdit) render() []byte {
	var lines []string
	for i := range e.f.lines {
		lines = append(lines, e.before[i]...)
		lines = append(lines, e.out[i]...)
	}
	lines = append(lines, e.before[len(e.f.lines)]...)
	for _, path := range e.tableOrder {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "["+encodeTOMLKey(path)+"]")
		lines = append(lines, e.newTables[pathKey(path)]...)
	}
	if len(lines) == 0 {
		return []byte{}
	}
	eol := "\n"
	if e.f.crlf {
		eol = "\r\n"
	}
	return []byte(strings.Join(lines, eol) + eol)
}

// dottedTable reports whether path is a table holding values but no [header],
// which TOML does not let a later header extend.
func dottedTable(doc map[string]any, path []string) bool {
	cur := doc
	for _, k := range path {
		m, ok := cur[k].(map[string]any)
		if !ok {
			return false
		}
		cur = m
	}
	for _, v := range cur {
		if _, ok := v.(map[string]any); !ok {
			return true
		}
	}
	return false
}

func (f *tomlFile) section(path []string) *tomlSection {
	for i := range f.sections {
		if !f.sections[i].array && pathKey(f.sections[i].path) == pathKey(path) {
			return &f.sections[i]
		}
	}
	return nil
}

type tomlLeaf struct {
	path  []string
	value any
}

func tomlLeaves(doc map[string]any, prefix []string) map[string]tomlLeaf {
	out := map[string]tomlLeaf{}
	for k, v := range doc {
		p := append(append([]string{}, prefix...), k)
		if m, ok := v.(map[string]any); ok {
			for lk, l := range tomlLeaves(m, p) {
				out[lk] = l
			}
			continue
		}
		out[pathKey(p)] = tomlLeaf{path: p, value: v}
	}
	return out
}

func sortedLeafKeys(m map[string]tomlLeaf) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sameJSON(a, b any) bool {
	ca, err1 := canonical(a)
	cb, err2 := canonical(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

// encodeTOMLValue writes a scalar. A value restored from the record arrives
// as a JSON-decoded string, number or boolean.
// ponytail: a raw value (array, date) NetBird overwrote comes back from undo
// as a quoted string; keeping its TOML type in the record is the upgrade if
// --force over such values matters.
func encodeTOMLValue(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return `"` + jsonEscape(v) + `"`, nil
	case bool:
		return strconv.FormatBool(v), nil
	case json.Number:
		return v.String(), nil
	case tomlRaw:
		return string(v), nil
	default:
		return "", fmt.Errorf("cannot write %T as TOML", v)
	}
}

func encodeTOMLKey(path []string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		if tomlBareKey.MatchString(p) {
			parts[i] = p
		} else {
			parts[i] = `"` + jsonEscape(p) + `"`
		}
	}
	return strings.Join(parts, ".")
}
