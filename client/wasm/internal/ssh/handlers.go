//go:build js

package ssh

import (
	"io"
	"syscall/js"
	"time"

	"github.com/sirupsen/logrus"
)

// How long an exec runs before it is abandoned, when the caller names no
// timeout. Long enough for a package install, short enough that a command
// waiting on a prompt nobody can answer does not hang forever.
const defaultExecTimeout = 5 * time.Minute

// createPromise runs fn on its own goroutine and hands it the promise's
// settle functions. The goroutine matters: fn blocks on the network, and the
// wasm event loop is what JS resolution runs on.
func createPromise(fn func(resolve, reject js.Value)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go fn(resolve, reject)
		return js.Undefined()
	})
	return js.Global().Get("Promise").New(handler)
}

// CreateJSInterface creates a JavaScript interface for the SSH client
func CreateJSInterface(client *Client) js.Value {
	jsInterface := js.Global().Get("Object").Call("create", js.Null())

	writeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf(false)
		}

		data := args[0]
		var bytes []byte

		if data.Type() == js.TypeString {
			bytes = []byte(data.String())
		} else {
			uint8Array := js.Global().Get("Uint8Array").New(data)
			length := uint8Array.Get("length").Int()
			bytes = make([]byte, length)
			js.CopyBytesToGo(bytes, uint8Array)
		}

		_, err := client.Write(bytes)
		return js.ValueOf(err == nil)
	})
	jsInterface.Set("write", writeFunc)

	resizeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf(false)
		}
		cols := args[0].Int()
		rows := args[1].Int()
		err := client.Resize(cols, rows)
		return js.ValueOf(err == nil)
	})
	jsInterface.Set("resize", resizeFunc)

	closeFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		client.Close()
		return js.Undefined()
	})
	jsInterface.Set("close", closeFunc)

	/*
	   `exec` runs one command in its own session and resolves with
	   {stdout, stderr, exitCode}. It is separate from `write` on purpose: that
	   one types into an interactive shell, where output is echoed, interleaved
	   with the prompt, dressed in terminal escapes and never accompanied by an
	   exit status. A caller that has to know whether a command SUCCEEDED
	   cannot use it.

	   A non-zero exit resolves rather than rejects. Rejecting would make a
	   command that ran and returned 1 indistinguishable from one that could not
	   be run at all, and those need different answers.
	*/
	execFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 || args[0].Type() != js.TypeString {
			return js.ValueOf("error: requires a command string")
		}
		command := args[0].String()
		timeout := defaultExecTimeout
		if len(args) > 1 && args[1].Type() == js.TypeNumber {
			if ms := args[1].Int(); ms > 0 {
				timeout = time.Duration(ms) * time.Millisecond
			}
		}
		return createPromise(func(resolve, reject js.Value) {
			result, err := client.RunCommand(command, timeout)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(js.ValueOf(map[string]any{
				"stdout":   result.Stdout,
				"stderr":   result.Stderr,
				"exitCode": result.ExitCode,
			}))
		})
	})
	jsInterface.Set("exec", execFunc)

	go func() {
		readLoop(client, jsInterface)
		// Detach before releasing so late JS calls surface as TypeError instead
		// of silent "call to released function".
		jsInterface.Set("write", js.Undefined())
		jsInterface.Set("resize", js.Undefined())
		jsInterface.Set("close", js.Undefined())
		jsInterface.Set("exec", js.Undefined())
		writeFunc.Release()
		resizeFunc.Release()
		closeFunc.Release()
		execFunc.Release()
	}()

	return jsInterface
}

func readLoop(client *Client, jsInterface js.Value) {
	buffer := make([]byte, 4096)
	for {
		n, err := client.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logrus.Debugf("SSH read error: %v", err)
			}
			if onclose := jsInterface.Get("onclose"); !onclose.IsUndefined() {
				onclose.Invoke()
			}
			client.Close()
			return
		}

		if ondata := jsInterface.Get("ondata"); !ondata.IsUndefined() {
			uint8Array := js.Global().Get("Uint8Array").New(n)
			js.CopyBytesToJS(uint8Array, buffer[:n])
			ondata.Invoke(uint8Array)
		}
	}
}
