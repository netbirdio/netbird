// +build linux

package iface

// Holds logic to check existence of Wireguard kernel module
// Copied from https://github.com/paultag/go-modprobe

import (
	"debug/elf"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

var (
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

	return filepath.Join(
		"/lib/modules",
		string(uname.Release[:i]),
	)
}

// modName will, given a file descriptor to a Kernel Module (.ko file), parse the
// binary to get the module name. For instance, given a handle to the file at
// `kernel/drivers/usb/gadget/legacy/g_ether.ko`, return `g_ether`.
func modName(file *os.File) (string, error) {
	f, err := elf.NewFile(file)
	if err != nil {
		return "", err
	}

	syms, err := f.Symbols()
	if err != nil {
		return "", err
	}

	for _, sym := range syms {
		if strings.Compare(sym.Name, "__this_module") == 0 {
			section := f.Sections[sym.Section]
			data, err := section.Data()
			if err != nil {
				return "", err
			}

			if len(data) < 25 {
				return "", fmt.Errorf("modprobe: data is short, __this_module is '%s'", data)
			}

			data = data[24:]
			i := 0
			for ; data[i] != 0x00; i++ {
			}
			return string(data[:i]), nil
		}
	}

	return "", fmt.Errorf("No name found. Is this a .ko or just an ELF?")
}

// Open every single kernel module under the root, and parse the ELF headers to
// extract the module name.
func elfMap(root string) (map[string]string, error) {
	ret := map[string]string{}

	err := filepath.Walk(
		root,
		func(path string, info os.FileInfo, err error) error {

			if err != nil {
				// skip broken files
				return nil
			}

			if !info.Mode().IsRegular() {
				return nil
			}
			fd, err := os.Open(path)
			if err != nil {
				return err
			}
			defer fd.Close()
			name, err := modName(fd)
			if err != nil {
				/* For now, let's just ignore that and avoid adding to it */
				return nil
			}

			ret[name] = path
			return nil
		})

	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Open every single kernel module under the kernel module directory
// (/lib/modules/$(uname -r)/), and parse the ELF headers to extract the
// module name.
func generateMap() (map[string]string, error) {
	return elfMap(moduleRoot)
}

// WireguardModExists returns true if Wireguard kernel module exists.
func WireguardModExists() bool {
	_, err := resolveModName("wireguard")
	return err == nil
}

// resolveModName will, given a module name (such as `wireguard`) return an absolute
// path to the .ko that provides that module.
func resolveModName(name string) (string, error) {
	paths, err := generateMap()
	if err != nil {
		return "", err
	}

	fsPath := paths[name]
	if !strings.HasPrefix(fsPath, moduleRoot) {
		return "", fmt.Errorf("module isn't in the module directory")
	}

	return fsPath, nil
}
