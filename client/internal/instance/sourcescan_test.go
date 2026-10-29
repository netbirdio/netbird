package instance_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// forbiddenExact are string literals the identity package derives. Outside it,
// the value must come from the package (SBS-ID-04).
var forbiddenExact = []string{
	"Netbird",
	"Netbird-v6",
	"NetBird-",
	"wt0",
	"utun100",
	"io.netbird.ui",
	"99-netbird.conf",
	"npipe://netbird",
	"unix:///var/run/netbird.sock",
	"tmp-install",
}

// forbiddenSubstrings are fragments of derived identifiers.
var forbiddenSubstrings = []string{
	"f2f29e61-d91f-4d76-8151-119b20c4bdeb",
	"QuickActionsTriggerEvent",
	"DebugTriggerEvent",
	"netbird-http.sock",
	"127.0.0.1:41731",
	"127.0.0.1:9191",
	"localhost:6969",
	`\Netbird\`,
	"netbird.debug",
}

// T-ID-04: no derived identifier is hard-coded in the client outside the
// identity package. Tests are exempt: they pin values on purpose.
func TestNoHardCodedIdentifiers(t *testing.T) {
	root := filepath.Join("..", "..")
	pkgDir, err := filepath.Abs(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipDir(path, d, pkgDir)
		}
		if !isScannedFile(path) {
			return nil
		}
		findings, err := scanFile(fset, path, nil)
		if err != nil {
			return err
		}
		scanned++
		for _, f := range findings {
			t.Errorf("%s: derived identifier hard-coded; take it from client/internal/instance", f)
		}
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, scanned, 500, "files scanned")
}

func TestSourceScanFindsLiterals(t *testing.T) {
	src := `package x
// "wt0" in a comment is fine
var a = "wt0"
var b = filepath.Join(os.Getenv("PROGRAMDATA"), "Netbird")
var c = ` + "`Global\\NetBirdQuickActionsTriggerEvent`" + `
var d = "NetBird-SSH-Server"
`
	findings, err := scanFile(token.NewFileSet(), "x.go", src)
	require.NoError(t, err)
	require.Len(t, findings, 3, "findings: %v", findings)
}

func scanFile(fset *token.FileSet, path string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var findings []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if v, err := strconv.Unquote(lit.Value); err == nil && isForbidden(v) {
			findings = append(findings, fset.Position(lit.Pos()).String()+" "+strconv.Quote(v))
		}
		return true
	})
	return findings, nil
}

func skipDir(path string, d fs.DirEntry, pkgDir string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if abs == pkgDir || d.Name() == "node_modules" || d.Name() == "testdata" {
		return filepath.SkipDir
	}
	return nil
}

func isScannedFile(path string) bool {
	return strings.HasSuffix(path, ".go") &&
		!strings.HasSuffix(path, "_test.go") &&
		!strings.HasSuffix(path, ".pb.go")
}

func isForbidden(v string) bool {
	for _, f := range forbiddenExact {
		if v == f {
			return true
		}
	}
	for _, f := range forbiddenSubstrings {
		if strings.Contains(v, f) {
			return true
		}
	}
	return false
}

func TestSourceScanRootIsClient(t *testing.T) {
	_, err := os.Stat(filepath.Join("..", "..", "cmd", "root.go"))
	require.NoError(t, err, "the scan must start at client/")
}
