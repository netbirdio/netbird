package config

import "golang.org/x/sys/windows"

func shortExecPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	buf := make([]uint16, len(path)+1)
	for {
		n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
}
