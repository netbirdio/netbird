package iface

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestGetModuleDependencies(t *testing.T) {
	testCases := []struct {
		name     string
		module   string
		expected []module
	}{
		{
			name:   "Get Single Dependency",
			module: "bar",
			expected: []module{
				{name: "foo", path: "kernel/a/foo.ko"},
			},
		},
		{
			name:   "Get Multiple Dependencies",
			module: "baz",
			expected: []module{
				{name: "foo", path: "kernel/a/foo.ko"},
				{name: "bar", path: "kernel/a/bar.ko"},
			},
		},
		{
			name:     "Get No Dependencies",
			module:   "foo",
			expected: []module{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer resetGlobals()
			_, _ = createFiles(t)
			modules, err := getModuleDependencies(testCase.module)
			require.NoError(t, err)

			expected := testCase.expected
			for i := range expected {
				expected[i].path = moduleRoot + "/" + expected[i].path
			}

			require.ElementsMatchf(t, modules, expected, "returned modules should match")
		})
	}
}

func TestIsBuiltinModule(t *testing.T) {
	testCases := []struct {
		name     string
		module   string
		expected bool
	}{
		{
			name:     "Built In Should Return True",
			module:   "foo_bi",
			expected: true,
		},
		{
			name:     "Not Built In Should Return False",
			module:   "not_built_in",
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer resetGlobals()
			_, _ = createFiles(t)

			isBuiltIn, err := isBuiltinModule(testCase.module)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, isBuiltIn)
		})
	}
}

func TestModuleStatus(t *testing.T) {
	random, err := getRandomLoadedModule(t)
	if err != nil {
		t.Fatal("should be able to get random module")
	}
	testCases := []struct {
		name           string
		module         string
		shouldBeLoaded bool
	}{
		{
			name:           "Should Return Module Loading Or Greater Status",
			module:         random,
			shouldBeLoaded: true,
		},
		{
			name:           "Should Return Module Unloaded Or Lower Status",
			module:         "not_loaded_module",
			shouldBeLoaded: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			defer resetGlobals()
			_, _ = createFiles(t)

			state, err := moduleStatus(testCase.module)
			require.NoError(t, err)
			if testCase.shouldBeLoaded {
				require.GreaterOrEqual(t, loading, state, "moduleStatus for %s should return state loading", testCase.module)
			} else {
				require.Less(t, state, loading, "module should return state unloading or lower")
			}
		})
	}
}

func resetGlobals() {
	moduleLibDir = defaultModuleDir
	moduleRoot = getModuleRoot()
}

func createFiles(t *testing.T) (string, []module) {
    t.Helper()
	writeFile := func(path, text string) {
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}

	moduleLibDir = t.TempDir()

	moduleRoot = getModuleRoot()
	if err := os.Mkdir(moduleRoot, 0755); err != nil {
		t.Fatal(err)
	}

	text := "kernel/a/foo.ko:\n"
	text += "kernel/a/bar.ko: kernel/a/foo.ko\n"
	text += "kernel/a/baz.ko: kernel/a/bar.ko kernel/a/foo.ko\n"
	writeFile(filepath.Join(moduleRoot, "/modules.dep"), text)

	text = "kernel/a/foo_bi.ko\n"
	text += "kernel/a/bar-bi.ko.gz\n"
	writeFile(filepath.Join(moduleRoot, "/modules.builtin"), text)

	modules := []module{
		{name: "foo", path: "kernel/a/foo.ko"},
		{name: "bar", path: "kernel/a/bar.ko"},
		{name: "baz", path: "kernel/a/baz.ko"},
	}
	return moduleLibDir, modules
}

func getRandomLoadedModule(t *testing.T) (string, error) {
    t.Helper()
	f, err := os.Open("/proc/modules")
	if err != nil {
		return "", err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			t.Logf("failed closing /proc/modules file, %v", err)
		}
	}()
	lines, err := lineCounter(f)
	if err != nil {
		return "", err
	}
	counter := 1
	midLine := lines / 2
	modName := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if counter == midLine {
			if fields[4] == "Unloading" {
				continue
			}
			modName = fields[0]
			break
		}
		counter++
	}
	if scanner.Err() != nil {
		return "", scanner.Err()
	}
	return modName, nil
}
func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}
