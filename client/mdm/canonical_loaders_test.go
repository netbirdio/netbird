//go:build windows || darwin

package mdm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"testing"
)

// TestAllKeysCoversEveryPolicyKey guards against the drift that adding a Key*
// constant without listing it in allKeys causes: the desktop loaders resolve
// value names through canonicalKey, so an unlisted key is silently discarded as
// unknown. policy.go is parsed rather than hand-mirrored so the test cannot go
// stale in the same way.
func TestAllKeysCoversEveryPolicyKey(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "policy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse policy.go: %v", err)
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			name := value.Names[0].Name
			if len(name) < 4 || name[:3] != "Key" {
				continue
			}
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquote %s: %v", name, err)
			}
			if !slices.Contains(allKeys, key) {
				t.Errorf("%s (%q) is missing from allKeys, so the desktop loaders discard it as unknown", name, key)
			}
		}
	}
}
