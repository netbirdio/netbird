//go:build windows

package services

import (
	"syscall"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/w32"
)

var procAttachThreadInput = syscall.NewLazyDLL("user32.dll").NewProc("AttachThreadInput")

func attachThreadInput(attach, attachTo w32.HANDLE, on bool) {
	var flag uintptr
	if on {
		flag = 1
	}
	_, _, _ = procAttachThreadInput.Call(uintptr(attach), uintptr(attachTo), flag)
}

func raiseToForeground(w *application.WebviewWindow) {
	if w == nil {
		return
	}
	application.InvokeSync(func() {
		ptr := w.NativeWindow()
		if ptr == nil {
			return
		}
		hwnd := w32.HWND(uintptr(ptr))

		fgThread, _ := w32.GetWindowThreadProcessId(w32.GetForegroundWindow())
		appThread := w32.GetCurrentThreadId()
		if fgThread != appThread {
			attachThreadInput(fgThread, appThread, true)
			defer attachThreadInput(fgThread, appThread, false)
		}
		w32.ShowWindow(hwnd, w32.SW_SHOW)
		w32.BringWindowToTop(hwnd)
		w32.SetForegroundWindow(hwnd)
	})
}
