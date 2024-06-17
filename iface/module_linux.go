//go:build linux && !android

// Package iface provides wireguard network interface creation and management
package iface

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Holds logic to check existence of kernel modules used by wireguard interfaces
// Copied from https://github.com/paultag/go-modprobe and
// https://github.com/pmorjan/kmod

type status int

const (
	defaultModuleDir        = "/lib/modules"
	unknown          status = iota
	unloaded
	unloading
	loading
	live
	inuse
	envDisableWireGuardKernel = "NB_WG_KERNEL_DISABLED"
)

type module struct {
	name string
	path string
}

var (
	// ErrModuleNotFound is the error resulting if a module can't be found.
	ErrModuleNotFound = errors.New("module not found")
	moduleLibDir      = defaultModuleDir
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

	return filepath.Join(moduleLibDir, string(uname.Release[:i]))
}

// tunModuleIsLoaded check if tun module exist, if is not attempt to load it
func tunModuleIsLoaded() bool {
	_, err := os.Stat("/dev/net/tun")
	if err == nil {
		return true
	}

	log.Infof("couldn't access device /dev/net/tun, go error %v, "+
		"will attempt to load tun module, if running on container add flag --cap-add=NET_ADMIN", err)

	tunLoaded, err := tryToLoadModule("tun")
	if err != nil {
		log.Errorf("unable to find or load tun module, got error: %v", err)
	}
	return tunLoaded
}

// WireGuardModuleIsLoaded check if we can load WireGuard mod (linux only)
func WireGuardModuleIsLoaded() bool {

	if os.Getenv(envDisableWireGuardKernel) == "true" {
		log.Debugf("WireGuard kernel module disabled because the %s env is set to true", envDisableWireGuardKernel)
		return false
	}

	if canCreateFakeWireGuardInterface() {
		return true
	}

	loaded, err := tryToLoadModule("wireguard")
	if err != nil {
		log.Info(err)
		return false
	}

	return loaded
}

func canCreateFakeWireGuardInterface() bool {
	link := newWGLink("mustnotexist")

	// We willingly try to create a device with an invalid
	// MTU here as the validation of the MTU will be performed after
	// the validation of the link kind and hence allows us to check
	// for the existence of the wireguard module without actually
	// creating a link.
	//
	// As a side-effect, this will also let the kernel lazy-load
	// the wireguard module.
	link.attrs.MTU = math.MaxInt

	err := netlink.LinkAdd(link)

	return errors.Is(err, syscall.EINVAL)
}

func tryToLoadModule(moduleName string) (bool, error) {
	if isModuleEnabled(moduleName) {
		return true, nil
	}
	modulePath, err := getModulePath(moduleName)
	if err != nil {
		return false, fmt.Errorf("couldn't find module path for %s, error: %v", moduleName, err)
	}
	if modulePath == "" {
		return false, nil
	}

	log.Infof("trying to load %s module", moduleName)

	err = loadModuleWithDependencies(moduleName, modulePath)
	if err != nil {
		return false, fmt.Errorf("couldn't load %s module, error: %v", moduleName, err)
	}
	return true, nil
}

func isModuleEnabled(name string) bool {
	builtin, builtinErr := isBuiltinModule(name)
	state, statusErr := moduleStatus(name)
	return (builtinErr == nil && builtin) || (statusErr == nil && state >= loading)
}

func getModulePath(name string) (string, error) {
	var foundPath string
	skipRemainingDirs := false

	err := filepath.WalkDir(
		moduleRoot,
		func(path string, info fs.DirEntry, err error) error {
			if skipRemainingDirs {
				return fs.SkipDir
			}
			if err != nil {
				// skip broken files
				return nil //nolint:nilerr
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

func isBuiltinModule(name string) (bool, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.builtin"))
	if err != nil {
		return false, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("failed closing modules.builtin file, %v", err)
		}
	}()

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
//
//	     name | memory size | reference count | references | state: <Live|Loading|Unloading>
//			macvlan 28672 1 macvtap, Live 0x0000000000000000
func moduleStatus(name string) (status, error) {
	state := unknown
	f, err := os.Open("/proc/modules")
	if err != nil {
		return state, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("failed closing /proc/modules file, %v", err)
		}
	}()

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

func loadModuleWithDependencies(name, path string) error {
	deps, err := getModuleDependencies(name)
	if err != nil {
		return fmt.Errorf("couldn't load list of module %s dependencies", name)
	}
	for _, dep := range deps {
		err = loadModule(dep.name, dep.path)
		if err != nil {
			return fmt.Errorf("couldn't load dependency module %s for %s", dep.name, name)
		}
	}
	return loadModule(name, path)
}

func loadModule(name, path string) error {
	state, err := moduleStatus(name)
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
	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("failed closing %s file, %v", path, err)
		}
	}()

	// first try finit_module(2), then init_module(2)
	err = unix.FinitModule(int(f.Fd()), "", 0)
	if errors.Is(err, unix.ENOSYS) {
		buf, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		return unix.InitModule(buf, "")
	}
	return err
}

// getModuleDependencies returns a module dependencies
func getModuleDependencies(name string) ([]module, error) {
	f, err := os.Open(filepath.Join(moduleRoot, "/modules.dep"))
	if err != nil {
		return nil, err
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Errorf("failed closing modules.dep file, %v", err)
		}
	}()

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
