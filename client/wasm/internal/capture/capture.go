//go:build js

// Package capture bridges the util/capture package to JavaScript via syscall/js.
package capture

import (
	"strings"
	"sync"
	"syscall/js"

	netbird "github.com/netbirdio/netbird/client/embed"
)

// Handle holds a running capture session so it can be stopped later.
type Handle struct {
	cs      *netbird.CaptureSession
	stopFn  js.Func
	stopped bool
}

// Stop ends the capture and returns stats.
func (h *Handle) Stop() netbird.CaptureStats {
	if h.stopped {
		return h.cs.Stats()
	}
	h.stopped = true
	h.stopFn.Release()

	h.cs.Stop()
	return h.cs.Stats()
}

func statsToJS(s netbird.CaptureStats) js.Value {
	obj := js.Global().Get("Object").Call("create", js.Null())
	obj.Set("packets", js.ValueOf(s.Packets))
	obj.Set("bytes", js.ValueOf(s.Bytes))
	obj.Set("dropped", js.ValueOf(s.Dropped))
	return obj
}

// parseOpts extracts filter/verbose/ascii from a JS options value.
func parseOpts(jsOpts js.Value) (filter string, verbose, ascii bool) {
	if jsOpts.IsNull() || jsOpts.IsUndefined() {
		return
	}
	if jsOpts.Type() == js.TypeString {
		filter = jsOpts.String()
		return
	}
	if jsOpts.Type() != js.TypeObject {
		return
	}
	if f := jsOpts.Get("filter"); !f.IsUndefined() && !f.IsNull() {
		filter = f.String()
	}
	if v := jsOpts.Get("verbose"); !v.IsUndefined() {
		verbose = v.Truthy()
	}
	if a := jsOpts.Get("ascii"); !a.IsUndefined() {
		ascii = a.Truthy()
	}
	return
}

// Start creates a capture session and returns a JS interface for streaming text
// output. The returned object exposes:
//
//	onpacket(callback)  - set callback(string) for each text line
//	stop()              - stop capture and return stats { packets, bytes, dropped }
//
// Options: { filter: string, verbose: bool, ascii: bool } or just a filter string.
func Start(client *netbird.Client, jsOpts js.Value) (js.Value, error) {
	filter, verbose, ascii := parseOpts(jsOpts)

	cb := &jsCallbackWriter{}

	cs, err := client.StartCapture(netbird.CaptureOptions{
		TextOutput: cb,
		Filter:     filter,
		Verbose:    verbose,
		ASCII:      ascii,
	})
	if err != nil {
		return js.Undefined(), err
	}

	handle := &Handle{cs: cs}

	iface := js.Global().Get("Object").Call("create", js.Null())
	handle.stopFn = js.FuncOf(func(_ js.Value, _ []js.Value) any {
		return statsToJS(handle.Stop())
	})
	iface.Set("stop", handle.stopFn)
	iface.Set("onpacket", js.Undefined())
	cb.setInterface(iface)

	return iface, nil
}

// StartConsole starts a capture that logs every packet line to console.log.
// Returns a Handle so the caller can stop it later.
func StartConsole(client *netbird.Client, jsOpts js.Value) (*Handle, error) {
	filter, verbose, ascii := parseOpts(jsOpts)

	cb := &jsCallbackWriter{}

	cs, err := client.StartCapture(netbird.CaptureOptions{
		TextOutput: cb,
		Filter:     filter,
		Verbose:    verbose,
		ASCII:      ascii,
	})
	if err != nil {
		return nil, err
	}

	handle := &Handle{cs: cs}
	handle.stopFn = js.FuncOf(func(_ js.Value, _ []js.Value) any {
		return statsToJS(handle.Stop())
	})

	iface := js.Global().Get("Object").Call("create", js.Null())
	console := js.Global().Get("console")
	iface.Set("onpacket", console.Get("log").Call("bind", console, js.ValueOf("[capture]")))
	cb.setInterface(iface)

	return handle, nil
}

// jsCallbackWriter is an io.Writer that buffers text until a newline, then
// invokes the JS onpacket callback with each complete line.
type jsCallbackWriter struct {
	mu    sync.Mutex
	iface js.Value
	buf   strings.Builder
}

func (w *jsCallbackWriter) setInterface(iface js.Value) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.iface = iface
}

func (w *jsCallbackWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)

	var lines []string
	for {
		str := w.buf.String()
		idx := strings.IndexByte(str, '\n')
		if idx < 0 {
			break
		}
		lines = append(lines, str[:idx])
		w.buf.Reset()
		if idx+1 < len(str) {
			w.buf.WriteString(str[idx+1:])
		}
	}

	iface := w.iface
	w.mu.Unlock()

	if iface.IsUndefined() {
		return len(p), nil
	}
	cb := iface.Get("onpacket")
	if cb.IsUndefined() || cb.IsNull() {
		return len(p), nil
	}
	for _, line := range lines {
		cb.Invoke(js.ValueOf(line))
	}
	return len(p), nil
}
