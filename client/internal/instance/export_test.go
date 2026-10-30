package instance

import "runtime"

// NewForOS builds an installation for any platform and environment, so every
// platform's identifiers can be tested on one host.
func NewForOS(goos string, env map[string]string, name Name, label string) Instance {
	return newInstance(goos, func(k string) string { return env[k] }, name, label)
}

// ExportGOOS returns the platform an installation was built for.
func ExportGOOS(i Instance) string {
	return i.goos
}

func goosOfHost() string {
	return runtime.GOOS
}
