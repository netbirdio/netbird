//go:build !windows && !android && !ios && !freebsd && !js

package main

func endSessionInterceptor() func(hwnd uintptr, msg uint32, wParam, lParam uintptr) (uintptr, bool) {
	return nil
}
