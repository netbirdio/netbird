package iface

// Holds logic to check existence of Wireguard kernel module
// Copied from https://github.com/paultag/go-modprobe and
// https://github.com/pmorjan/kmod

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type status int

const (
	unknown status = iota
	unloaded
	unloading
	loading
	live
	inuse
)

type module struct {
	name string
	path string
}

var (
	// ErrModuleNotFound is the error resulting if a module can't be found.
	ErrModuleNotFound = errors.New("module not found")
	// get the root directory for the kernel modules. If this line panics,
	// it's because getModuleRoot has failed to get the uname of the running
	// kernel (likely a non-POSIX system, but maybe a broken kernel?)
	moduleRoot = getModuleRoot()
)

// Get the module root (/lib/modules/$(uname -r)/)
func getModuleRoot() string {
	uname := unix.Utsname{}
	if err := unix.Uname(&uname); err != nil {
		panic(err)
	}

	i := 0
	for ; uname.Release[i] != 0; i++ {
	}

	return filepath.Join("/lib/modules", string(uname.Release[:i]))
}

// resolveModName will, given a module name (such as `wireguard`) return an absolute
// path to the .ko that provides that module.
func resolveModPath(name string) (string, error) {
	fsPath, err := getModulePath(moduleRoot, name)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(fsPath, moduleRoot) {
		return "", fmt.Errorf("module isn't in the module directory")
	}

	return fsPath, nil
}

// Open every single kernel module under the root, and parse the ELF headers to
// extract the module name.
func getModulePath(root string, name string) (string, error) {
	var foundPath string
	skipRemainingDirs := false

	err := filepath.WalkDir(
		root,
		func(path string, info fs.DirEntry, err error) error {
			if skipRemainingDirs {
				return fs.SkipDir
			}
			if err != nil {
				// skip broken files
				return nil
			}

			if !info.Type().IsRegular() {
				return nil
			}

			nameFromPath := pathToName(path)
			if nameFromPath == name {
				foundPath = path
				skipRemainingDirs = true
			}

			return nil
		})

	if err != nil {
		return "", err
	}

	return foundPath, nil
}

func pathToName(s string) string {
	s = filepath.Base(s)
	for ext := filepath.Ext(s); ext != ""; ext = filepath.Ext(s) {
		s = strings.TrimSuffix(s, ext)
	}
	return cleanName(s)
}

func cleanName(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

func isBuiltin(name string) (bool, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.builtin"))
	if err != nil {
		return false, err
	}
	defer f.Close()

	var found bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if pathToName(line) == name {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return found, nil
}

// /proc/modules
//      name | memory size | reference count | references | state: <Live|Loading|Unloading>
// 		macvlan 28672 1 macvtap, Live 0x0000000000000000
func modStatus(name string) (status, error) {
	state := unknown
	f, err := os.Open("/proc/modules")
	if err != nil {
		return state, err
	}
	defer f.Close()

	state = unloaded

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if fields[0] == name {
			if fields[2] != "0" {
				state = inuse
				break
			}
			switch fields[4] {
			case "Live":
				state = live
			case "Loading":
				state = loading
			case "Unloading":
				state = unloading
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return state, err
	}

	return state, nil
}

func loadWithDeps(name, path string) error {
	deps, err := modDeps(name)
	if err != nil {
		return fmt.Errorf("couldn't load list of module %s dependecies", name)
	}
	for _, dep := range deps {
		err = load(dep.name, dep.path)
		if err != nil {
			return fmt.Errorf("couldn't load dependecy module %s for %s", dep.name, name)
		}
	}
	return load(name, path)
}

func load(name, path string) error {
	state, err := modStatus(name)
	if err != nil {
		return err
	}
	if state >= loading {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// first try finit_module(2), then init_module(2)
	err = unix.FinitModule(int(f.Fd()), "", 0)
	if errors.Is(err, unix.ENOSYS) {
		buf, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		return unix.InitModule(buf, "")
	}
	return err
}

// modDeps returns a module depenencies
func modDeps(name string) ([]module, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.dep"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if pathToName(strings.TrimSuffix(fields[0], ":")) == name {
			deps = fields
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(deps) == 0 {
		return nil, ErrModuleNotFound
	}
	deps[0] = strings.TrimSuffix(deps[0], ":")

	var modules []module
	for _, v := range deps {
		if pathToName(v) != name {
			modules = append(modules, module{
				name: pathToName(v),
				path: filepath.Join(moduleRoot, v),
			})
		}
	}

	return modules, nil
}
