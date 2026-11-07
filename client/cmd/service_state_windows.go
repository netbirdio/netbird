//go:build windows

package cmd

import (
	"golang.org/x/sys/windows"
)

// serviceState reports a service's state and whether it exists. It asks only
// for the rights a standard user has.
func serviceState(name string) (string, bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown", false
	}
	defer func() { _ = windows.CloseServiceHandle(scm) }()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "unknown", false
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "unknown", false
	}
	defer func() { _ = windows.CloseServiceHandle(h) }()

	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return "unknown", true
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running", true
	case windows.SERVICE_STOPPED:
		return "stopped", true
	case windows.SERVICE_START_PENDING:
		return "starting", true
	case windows.SERVICE_STOP_PENDING:
		return "stopping", true
	default:
		return "unknown", true
	}
}
