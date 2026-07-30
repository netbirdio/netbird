package version

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDownloadURL_HomebrewFormula(t *testing.T) {
	recordedArgs := installBrew(t, "list --formula netbird")

	if got := DownloadUrl(); got != downloadURL {
		t.Fatalf("DownloadUrl() = %q, want %q", got, downloadURL)
	}

	assertBrewArgs(t, recordedArgs, "list --formula netbird")
}

func TestDownloadURL_HomebrewCask(t *testing.T) {
	recordedArgs := installBrew(t, "list --cask netbird-ui")

	if got := DownloadUrl(); got != downloadURL {
		t.Fatalf("DownloadUrl() = %q, want %q", got, downloadURL)
	}

	assertBrewArgs(t, recordedArgs, "list --formula netbird\nlist --cask netbird-ui")
}

func TestDownloadURL_PackageFallback(t *testing.T) {
	recordedArgs := installBrew(t, "")

	want := urlMacIntel
	if runtime.GOARCH == "arm64" {
		want = urlMacM1M2
	}

	if got := DownloadUrl(); got != want {
		t.Fatalf("DownloadUrl() = %q, want %q", got, want)
	}

	assertBrewArgs(t, recordedArgs, "list --formula netbird\nlist --cask netbird-ui")
}

func installBrew(t *testing.T, successfulArgs string) string {
	t.Helper()

	dir := t.TempDir()
	recordedArgs := filepath.Join(dir, "brew-arguments")
	brew := filepath.Join(dir, "brew")
	script := "#!/bin/sh\n" +
		"printf '%s %s %s\\n' \"$1\" \"$2\" \"$3\" >> \"$BREW_ARGUMENTS_FILE\"\n" +
		"case \"$1 $2 $3\" in\n" +
		"  \"list --formula netbird\"|\"list --cask netbird-ui\") ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n" +
		"[ \"$1 $2 $3\" = \"$BREW_SUCCESSFUL_ARGS\" ]\n"
	if err := os.WriteFile(brew, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BREW_ARGUMENTS_FILE", recordedArgs)
	t.Setenv("BREW_SUCCESSFUL_ARGS", successfulArgs)
	t.Setenv("PATH", dir)

	return recordedArgs
}

func assertBrewArgs(t *testing.T, file, want string) {
	t.Helper()

	contents, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(string(contents)); got != want {
		t.Fatalf("brew arguments = %q, want %q", got, want)
	}
}
