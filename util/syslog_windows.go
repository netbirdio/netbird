package util

func AddSyslogHook() {
	// The syslog package is not available for Windows. This adapter is needed
	// to handle windows build.
}
