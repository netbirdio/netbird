//go:build js

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	netbird "github.com/netbirdio/netbird/client/embed"
	sshdetection "github.com/netbirdio/netbird/client/ssh/detection"
	nbstatus "github.com/netbirdio/netbird/client/status"
	wasmcapture "github.com/netbirdio/netbird/client/wasm/internal/capture"
	"github.com/netbirdio/netbird/client/wasm/internal/http"
	"github.com/netbirdio/netbird/client/wasm/internal/netutil"
	"github.com/netbirdio/netbird/client/wasm/internal/rdp"
	"github.com/netbirdio/netbird/client/wasm/internal/ssh"
	"github.com/netbirdio/netbird/client/wasm/internal/vnc"
	nbwebsocket "github.com/netbirdio/netbird/client/wasm/internal/websocket"
	"github.com/netbirdio/netbird/util"
)

const (
	clientStartTimeout         = 30 * time.Second
	clientStopTimeout          = 10 * time.Second
	pingTimeout                = 10 * time.Second
	defaultLogLevel            = "warn"
	defaultSSHDetectionTimeout = 20 * time.Second
	dialWebSocketTimeout       = 30 * time.Second

	icmpEchoRequest = 8
	icmpCodeEcho    = 0
	pingBufferSize  = 1500
)

func main() {
	js.Global().Set("NetBirdClient", js.FuncOf(netBirdClientConstructor))
	js.Global().Set("netbirdGenerateVNCSessionKey", createGenerateVNCSessionKeyMethod())

	select {}
}

func startClient(ctx context.Context, nbClient *netbird.Client) error {
	log.Info("Starting NetBird client...")
	if err := nbClient.Start(ctx); err != nil {
		return err
	}
	log.Info("NetBird client started successfully")
	return nil
}

// parseClientOptions extracts NetBird options from JavaScript object
func parseClientOptions(jsOptions js.Value) (netbird.Options, error) {
	options := netbird.Options{
		DeviceName: "dashboard-client",
		LogLevel:   defaultLogLevel,
	}

	if jwtToken := jsOptions.Get("jwtToken"); !jwtToken.IsNull() && !jwtToken.IsUndefined() {
		options.JWTToken = jwtToken.String()
	}

	if setupKey := jsOptions.Get("setupKey"); !setupKey.IsNull() && !setupKey.IsUndefined() {
		options.SetupKey = setupKey.String()
	}

	if privateKey := jsOptions.Get("privateKey"); !privateKey.IsNull() && !privateKey.IsUndefined() {
		options.PrivateKey = privateKey.String()
	}

	if mgmtURL := jsOptions.Get("managementURL"); !mgmtURL.IsNull() && !mgmtURL.IsUndefined() {
		mgmtURLStr := mgmtURL.String()
		if mgmtURLStr != "" {
			options.ManagementURL = mgmtURLStr
		}
	}

	if logLevel := jsOptions.Get("logLevel"); !logLevel.IsNull() && !logLevel.IsUndefined() {
		options.LogLevel = logLevel.String()
	}

	if deviceName := jsOptions.Get("deviceName"); !deviceName.IsNull() && !deviceName.IsUndefined() {
		options.DeviceName = deviceName.String()
	}

	if disableIPv6 := jsOptions.Get("disableIPv6"); !disableIPv6.IsNull() && !disableIPv6.IsUndefined() {
		options.DisableIPv6 = disableIPv6.Bool()
	}

	return options, nil
}

// createStartMethod creates the start method for the client
func createStartMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			ctx, cancel := context.WithTimeout(context.Background(), clientStartTimeout)
			defer cancel()

			if err := startClient(ctx, client); err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			resolve.Invoke(js.ValueOf(true))
		})
	})
}

// createStopMethod creates the stop method for the client
func createStopMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			ctx, cancel := context.WithTimeout(context.Background(), clientStopTimeout)
			defer cancel()

			if err := client.Stop(ctx); err != nil {
				log.Errorf("Error stopping client: %v", err)
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			log.Info("NetBird client stopped")
			resolve.Invoke(js.ValueOf(true))
		})
	})
}

// validateSSHArgs validates SSH connection arguments
func validateSSHArgs(args []js.Value) (host string, port int, username string, err js.Value) {
	if len(args) < 2 {
		return "", 0, "", js.ValueOf("error: requires host and port")
	}

	if args[0].Type() != js.TypeString {
		return "", 0, "", js.ValueOf("host parameter must be a string")
	}
	if args[1].Type() != js.TypeNumber {
		return "", 0, "", js.ValueOf("port parameter must be a number")
	}

	host = args[0].String()
	port = args[1].Int()
	username = "root"

	if len(args) > 2 {
		if args[2].Type() == js.TypeString && args[2].String() != "" {
			username = args[2].String()
		} else if args[2].Type() != js.TypeString {
			return "", 0, "", js.ValueOf("username parameter must be a string")
		}
	}

	return host, port, username, js.Undefined()
}

// createSSHMethod creates the SSH connection method
func createSSHMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		host, port, username, validationErr := validateSSHArgs(args)
		if !validationErr.IsUndefined() {
			if validationErr.Type() == js.TypeString && validationErr.String() == "error: requires host and port" {
				return validationErr
			}
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(validationErr)
			})
		}

		jwtToken, ipVersion := parseSSHOptions(args)

		return createPromise(func(resolve, reject js.Value) {
			jsInterface, err := connectSSH(client, host, port, username, jwtToken, ipVersion)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(jsInterface)
		})
	})
}

func parseSSHOptions(args []js.Value) (jwtToken string, ipVersion int) {
	if len(args) > 3 && !args[3].IsNull() && !args[3].IsUndefined() {
		jwtToken = args[3].String()
	}
	if len(args) > 4 {
		ipVersion = jsIPVersion(args[4])
	}
	return
}

func connectSSH(client *netbird.Client, host string, port int, username, jwtToken string, ipVersion int) (js.Value, error) {
	sshClient := ssh.NewClient(client)

	if err := sshClient.Connect(host, port, username, jwtToken, ipVersion); err != nil {
		return js.Undefined(), err
	}

	if err := sshClient.StartSession(80, 24); err != nil {
		if closeErr := sshClient.Close(); closeErr != nil {
			log.Errorf("Error closing SSH client: %v", closeErr)
		}
		return js.Undefined(), err
	}

	return ssh.CreateJSInterface(sshClient), nil
}

func performPing(client *netbird.Client, hostname string, ipVersion int) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	// Default to ping4 to avoid dual-stack ICMP endpoint issues in wireguard-go netstack.
	network := "ping4"
	if ipVersion == 6 {
		network = "ping6"
	}

	start := time.Now()
	conn, err := client.Dial(ctx, network, hostname)
	if err != nil {
		js.Global().Get("console").Call("log", fmt.Sprintf("Ping to %s failed: %v", hostname, err))
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("failed to close ping connection: %v", err)
		}
	}()

	icmpData := make([]byte, 8)
	icmpData[0] = icmpEchoRequest
	icmpData[1] = icmpCodeEcho

	if _, err := conn.Write(icmpData); err != nil {
		js.Global().Get("console").Call("log", fmt.Sprintf("Ping to %s write failed: %v", hostname, err))
		return
	}

	buf := make([]byte, pingBufferSize)
	if _, err := conn.Read(buf); err != nil {
		js.Global().Get("console").Call("log", fmt.Sprintf("Ping to %s read failed: %v", hostname, err))
		return
	}

	latency := time.Since(start)
	remote := conn.RemoteAddr().String()
	msg := fmt.Sprintf("Ping to %s: %dms", hostname, latency.Milliseconds())
	if remote != hostname {
		msg += fmt.Sprintf(" (via %s)", remote)
	}
	js.Global().Get("console").Call("log", msg)
}

func performPingTCP(client *netbird.Client, hostname string, port, ipVersion int) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	network := netutil.TCPNetwork(ipVersion)

	address := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := client.Dial(ctx, network, address)
	if err != nil {
		js.Global().Get("console").Call("log", fmt.Sprintf("TCP ping to %s failed: %v", address, err))
		return
	}
	latency := time.Since(start)

	remote := conn.RemoteAddr().String()
	if err := conn.Close(); err != nil {
		log.Debugf("failed to close TCP connection: %v", err)
	}

	msg := fmt.Sprintf("TCP ping to %s succeeded: %dms", address, latency.Milliseconds())
	if remote != address {
		msg += fmt.Sprintf(" (via %s)", remote)
	}
	js.Global().Get("console").Call("log", msg)
}

// createPingMethod creates the ping method
func createPingMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf("error: hostname required")
		}

		if args[0].Type() != js.TypeString {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("hostname parameter must be a string"))
			})
		}

		hostname := args[0].String()
		var ipVersion int
		if len(args) > 1 {
			ipVersion = jsIPVersion(args[1])
		}
		return createPromise(func(resolve, reject js.Value) {
			performPing(client, hostname, ipVersion)
			resolve.Invoke(js.Undefined())
		})
	})
}

// createPingTCPMethod creates the pingtcp method
func createPingTCPMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf("error: hostname and port required")
		}

		if args[0].Type() != js.TypeString {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("hostname parameter must be a string"))
			})
		}

		if args[1].Type() != js.TypeNumber {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("port parameter must be a number"))
			})
		}

		hostname := args[0].String()
		port := args[1].Int()
		var ipVersion int
		if len(args) > 2 {
			ipVersion = jsIPVersion(args[2])
		}
		return createPromise(func(resolve, reject js.Value) {
			performPingTCP(client, hostname, port, ipVersion)
			resolve.Invoke(js.Undefined())
		})
	})
}

// createProxyRequestMethod creates the proxyRequest method
func createProxyRequestMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf("error: request details required")
		}

		request := args[0]
		if request.Type() != js.TypeObject {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("request parameter must be an object"))
			})
		}

		return createPromise(func(resolve, reject js.Value) {
			response, err := http.ProxyRequest(client, request)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(response)
		})
	})
}

// createRDPProxyMethod creates the RDP proxy method
func createRDPProxyMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf("error: hostname and port required")
		}

		if args[0].Type() != js.TypeString {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("hostname parameter must be a string"))
			})
		}
		if args[1].Type() != js.TypeString {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("port parameter must be a string"))
			})
		}

		proxy := rdp.NewRDCleanPathProxy(client)
		return proxy.CreateProxy(args[0].String(), args[1].String())
	})
}

// createGenerateVNCSessionKeyMethod returns a JS func that mints a fresh
// X25519 keypair, stashes the private half inside wasm under a random
// session id, and returns { publicKey, sessionId } to JS. The private
// key never leaves the wasm heap.
func createGenerateVNCSessionKeyMethod() js.Func {
	return js.FuncOf(func(_ js.Value, _ []js.Value) any {
		id, pub, err := vnc.NewSessionKey()
		if err != nil {
			return js.ValueOf(err.Error())
		}
		out := js.Global().Get("Object").New()
		out.Set("sessionId", id)
		out.Set("publicKey", base64.StdEncoding.EncodeToString(pub))
		return out
	})
}

// createVNCProxyMethod creates the VNC proxy method for raw TCP-over-WebSocket bridging.
// JS signature: createVNCProxy(hostname, port, mode?, username?, keySessionID?, sessionID?, width?, height?, peerPublicKey?, ipVersion?)
//
//	mode:           "attach" (default) or "session"
//	username:       required when mode is "session"
//	keySessionID:   handle for the wasm-resident session keypair minted by netbirdGenerateVNCSessionKey
//	sessionID:      Windows session ID (0 = console/auto)
//	width/height:   requested viewport size for session mode (0 = server default)
//	peerPublicKey:  base64 X25519 static pubkey of the destination peer (required for auth)
//	ipVersion:      address family to dial: 4, 6, or 0/omitted for automatic
func createVNCProxyMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		params, err := parseVNCProxyArgs(args)
		if err != nil {
			if params.rejectViaPromise {
				return createPromise(func(resolve, reject js.Value) {
					reject.Invoke(js.ValueOf(err.Error()))
				})
			}
			return js.ValueOf(err.Error())
		}
		proxy := vnc.NewVNCProxy(client)
		return proxy.CreateProxy(vnc.ProxyRequest{
			Hostname:      params.hostname,
			Port:          params.port,
			Mode:          params.mode,
			Username:      params.username,
			SessionID:     params.sessionID,
			Width:         params.width,
			Height:        params.height,
			PeerPublicKey: params.peerPublicKey,
			KeySessionID:  params.keySessionID,
			IPVersion:     params.ipVersion,
		})
	})
}

type vncProxyParams struct {
	hostname         string
	port             string
	mode             string
	username         string
	keySessionID     string
	sessionID        uint32
	width            uint16
	height           uint16
	peerPublicKey    string
	ipVersion        int
	rejectViaPromise bool
}

// parseVNCProxyArgs validates JS args for createVNCProxyMethod and returns
// the parsed params plus the first validation error (nil on success).
// vncProxyParams.rejectViaPromise tells the caller which JS-side response
// path to use for the returned error.
func parseVNCProxyArgs(args []js.Value) (vncProxyParams, error) {
	var p vncProxyParams
	if err := parseVNCProxyRequiredArgs(args, &p); err != nil {
		return p, err
	}
	if err := parseVNCProxyOptionalStrings(args, &p); err != nil {
		return p, err
	}
	if err := parseVNCProxyOptionalNumbers(args, &p); err != nil {
		return p, err
	}
	return p, nil
}

func parseVNCProxyRequiredArgs(args []js.Value, p *vncProxyParams) error {
	if len(args) < 2 {
		return fmt.Errorf("hostname and port required")
	}
	if args[0].Type() != js.TypeString {
		p.rejectViaPromise = true
		return fmt.Errorf("hostname parameter must be a string")
	}
	if args[1].Type() != js.TypeString {
		p.rejectViaPromise = true
		return fmt.Errorf("port parameter must be a string")
	}
	p.hostname = args[0].String()
	p.port = args[1].String()
	p.mode = "attach"
	return nil
}

func parseVNCProxyOptionalStrings(args []js.Value, p *vncProxyParams) error {
	if len(args) > 2 && args[2].Type() == js.TypeString {
		p.mode = args[2].String()
	}
	if p.mode != "attach" && p.mode != "session" {
		p.rejectViaPromise = true
		return fmt.Errorf("invalid mode %q: expected \"attach\" or \"session\"", p.mode)
	}
	if len(args) > 3 && args[3].Type() == js.TypeString {
		p.username = args[3].String()
	}
	if len(args) > 4 && args[4].Type() == js.TypeString {
		p.keySessionID = args[4].String()
	}
	return nil
}

func parseVNCProxyOptionalNumbers(args []js.Value, p *vncProxyParams) error {
	if len(args) > 5 && args[5].Type() == js.TypeNumber {
		v := args[5].Int()
		if v < 0 || v > 0xFFFFFFFF {
			p.rejectViaPromise = true
			return fmt.Errorf("invalid sessionID %d: must be 0..0xFFFFFFFF", v)
		}
		p.sessionID = uint32(v)
	}
	// width=0 / height=0 mean "use server default"; reject only out-of-range
	// non-zero values so attach mode (which omits width/height) still works.
	if len(args) > 6 && args[6].Type() == js.TypeNumber {
		v := args[6].Int()
		if v < 0 || v > 0xFFFF {
			p.rejectViaPromise = true
			return fmt.Errorf("invalid width %d: must be 0..65535", v)
		}
		p.width = uint16(v)
	}
	if len(args) > 7 && args[7].Type() == js.TypeNumber {
		v := args[7].Int()
		if v < 0 || v > 0xFFFF {
			p.rejectViaPromise = true
			return fmt.Errorf("invalid height %d: must be 0..65535", v)
		}
		p.height = uint16(v)
	}
	if len(args) > 8 && args[8].Type() == js.TypeString {
		p.peerPublicKey = args[8].String()
	}
	if len(args) > 9 {
		p.ipVersion = jsIPVersion(args[9])
	}
	return nil
}

// getStatusOverview is a helper to get the status overview
func getStatusOverview(client *netbird.Client) (nbstatus.OutputOverview, error) {
	fullStatus, err := client.Status()
	if err != nil {
		return nbstatus.OutputOverview{}, err
	}

	pbFullStatus := fullStatus.ToProto()

	return nbstatus.ConvertToStatusOutputOverview(pbFullStatus, nbstatus.ConvertOptions{}), nil
}

// createStatusMethod creates the status method that returns JSON
func createStatusMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			overview, err := getStatusOverview(client)
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			jsonStr, err := overview.JSON()
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}
			jsonObj := js.Global().Get("JSON").Call("parse", jsonStr)
			resolve.Invoke(jsonObj)
		})
	})
}

// createStatusSummaryMethod creates the statusSummary method
func createStatusSummaryMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			overview, err := getStatusOverview(client)
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			summary := overview.GeneralSummary(false, false, false, false)
			js.Global().Get("console").Call("log", summary)
			resolve.Invoke(js.Undefined())
		})
	})
}

// createStatusDetailMethod creates the statusDetail method
func createStatusDetailMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			overview, err := getStatusOverview(client)
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			detail := overview.FullDetailSummary()
			js.Global().Get("console").Call("log", detail)
			resolve.Invoke(js.Undefined())
		})
	})
}

// createGetSyncResponseMethod creates the getSyncResponse method that returns the latest sync response as JSON
func createGetSyncResponseMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return createPromise(func(resolve, reject js.Value) {
			syncResp, err := client.GetLatestSyncResponse()
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			options := protojson.MarshalOptions{
				EmitUnpopulated: true,
				UseProtoNames:   true,
				AllowPartial:    true,
			}
			jsonBytes, err := options.Marshal(syncResp)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("marshal sync response: %v", err)))
				return
			}

			jsonObj := js.Global().Get("JSON").Call("parse", string(jsonBytes))
			resolve.Invoke(jsonObj)
		})
	})
}

// createSetLogLevelMethod creates the setLogLevel method to dynamically change logging level
func createSetLogLevelMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf("error: log level required")
		}

		if args[0].Type() != js.TypeString {
			return createPromise(func(resolve, reject js.Value) {
				reject.Invoke(js.ValueOf("log level parameter must be a string"))
			})
		}

		logLevel := args[0].String()
		return createPromise(func(resolve, reject js.Value) {
			if err := client.SetLogLevel(logLevel); err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("set log level: %v", err)))
				return
			}
			log.Infof("Log level set to: %s", logLevel)
			resolve.Invoke(js.ValueOf(true))
		})
	})
}

// jsIPVersion extracts an IP version (4 or 6) from a JS string or number.
func jsIPVersion(v js.Value) int {
	switch v.Type() {
	case js.TypeNumber:
		return v.Int()
	case js.TypeString:
		n, _ := strconv.Atoi(v.String())
		return n
	default:
		return 0
	}
}

// createStartCaptureMethod creates the programmable packet capture method.
// Returns a JS interface with onpacket callback and stop() method.
//
// Usage from JavaScript:
//
//	const cap = await client.startCapture({ filter: "tcp port 443", verbose: true })
//	cap.onpacket = (line) => console.log(line)
//	const stats = cap.stop()
func createStartCaptureMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		var opts js.Value
		if len(args) > 0 {
			opts = args[0]
		}

		return createPromise(func(resolve, reject js.Value) {
			iface, err := wasmcapture.Start(client, opts)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("start capture: %v", err)))
				return
			}
			resolve.Invoke(iface)
		})
	})
}

// captureMethods returns capture() and stopCapture() that share state for
// the console-log shortcut. capture() logs packets to the browser console
// and stopCapture() ends it, like Ctrl+C on the CLI.
//
// Usage from browser devtools console:
//
//	await netbird.capture()              // capture all packets
//	await netbird.capture("tcp")         // capture with filter
//	await netbird.capture({filter: "host 10.0.0.1", verbose: true})
//	netbird.stopCapture()                // stop and print stats
func captureMethods(client *netbird.Client) (startFn, stopFn js.Func) {
	var mu sync.Mutex
	var active *wasmcapture.Handle

	startFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		var opts js.Value
		if len(args) > 0 {
			opts = args[0]
		}

		return createPromise(func(resolve, reject js.Value) {
			mu.Lock()
			defer mu.Unlock()

			if active != nil {
				active.Stop()
				active = nil
			}

			h, err := wasmcapture.StartConsole(client, opts)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("start capture: %v", err)))
				return
			}
			active = h

			console := js.Global().Get("console")
			console.Call("log", "[capture] started, call netbird.stopCapture() to stop")
			resolve.Invoke(js.Undefined())
		})
	})

	stopFn = js.FuncOf(func(_ js.Value, _ []js.Value) any {
		mu.Lock()
		defer mu.Unlock()

		if active == nil {
			js.Global().Get("console").Call("log", "[capture] no active capture")
			return js.Undefined()
		}

		stats := active.Stop()
		active = nil

		console := js.Global().Get("console")
		console.Call("log", fmt.Sprintf("[capture] stopped: %d packets, %d bytes, %d dropped",
			stats.Packets, stats.Bytes, stats.Dropped))
		return js.Undefined()
	})

	return startFn, stopFn
}

// createPromise is a helper to create JavaScript promises
func createPromise(handler func(resolve, reject js.Value)) js.Value {
	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go handler(resolve, reject)

		return nil
	}))
}

// createDetectSSHServerMethod creates the SSH server detection method
func createDetectSSHServerMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf("error: requires host and port")
		}

		host := args[0].String()
		port := args[1].Int()

		timeoutMs := int(defaultSSHDetectionTimeout.Milliseconds())
		if len(args) >= 3 && !args[2].IsNull() && !args[2].IsUndefined() {
			timeoutMs = args[2].Int()
			if timeoutMs <= 0 {
				return js.ValueOf("error: timeout must be positive")
			}
		}

		return createPromise(func(resolve, reject js.Value) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
			defer cancel()

			serverType, err := sshdetection.DetectSSHServerType(ctx, client, host, port)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}

			resolve.Invoke(js.ValueOf(serverType.RequiresJWT()))
		})
	})
}

// createClientObject wraps the NetBird client in a JavaScript object
func createClientObject(client *netbird.Client) js.Value {
	obj := make(map[string]interface{})

	obj["start"] = createStartMethod(client)
	obj["stop"] = createStopMethod(client)
	obj["ping"] = createPingMethod(client)
	obj["pingtcp"] = createPingTCPMethod(client)
	obj["detectSSHServerType"] = createDetectSSHServerMethod(client)
	obj["createSSHConnection"] = createSSHMethod(client)
	obj["proxyRequest"] = createProxyRequestMethod(client)
	obj["createRDPProxy"] = createRDPProxyMethod(client)
	obj["createVNCProxy"] = createVNCProxyMethod(client)
	obj["dialWebSocket"] = createDialWebSocketMethod(client)
	obj["status"] = createStatusMethod(client)
	obj["statusSummary"] = createStatusSummaryMethod(client)
	obj["statusDetail"] = createStatusDetailMethod(client)
	obj["getSyncResponse"] = createGetSyncResponseMethod(client)
	obj["setLogLevel"] = createSetLogLevelMethod(client)
	obj["startCapture"] = createStartCaptureMethod(client)

	capStart, capStop := captureMethods(client)
	obj["capture"] = capStart
	obj["stopCapture"] = capStop

	return js.ValueOf(obj)
}

func createDialWebSocketMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		url, protocols, timeout, errVal := parseDialWebSocketArgs(args)
		if !errVal.IsUndefined() {
			return errVal
		}

		return createPromise(func(resolve, reject js.Value) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			conn, err := nbwebsocket.Dial(ctx, client, url, protocols)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("dial websocket: %v", err)))
				return
			}

			resolve.Invoke(nbwebsocket.NewJSInterface(conn))
		})
	})
}

func parseDialWebSocketArgs(args []js.Value) (url string, protocols []string, timeout time.Duration, errVal js.Value) {
	if len(args) < 1 || args[0].Type() != js.TypeString {
		return "", nil, 0, js.ValueOf("error: dialWebSocket requires a URL string argument")
	}
	url = args[0].String()

	if len(args) >= 2 && !args[1].IsNull() && !args[1].IsUndefined() {
		arr, err := jsStringArray(args[1])
		if err != nil {
			return "", nil, 0, js.ValueOf(fmt.Sprintf("error: protocols: %v", err))
		}
		protocols = arr
	}

	timeout = dialWebSocketTimeout
	if len(args) >= 3 && !args[2].IsNull() && !args[2].IsUndefined() {
		if args[2].Type() != js.TypeNumber {
			return "", nil, 0, js.ValueOf("error: timeoutMs must be a number")
		}
		timeoutMs := args[2].Int()
		if timeoutMs <= 0 {
			return "", nil, 0, js.ValueOf("error: timeout must be positive")
		}
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	return url, protocols, timeout, js.Undefined()
}

// jsStringArray converts a JS array of strings to a Go []string.
func jsStringArray(v js.Value) ([]string, error) {
	if !v.InstanceOf(js.Global().Get("Array")) {
		return nil, fmt.Errorf("expected array")
	}
	n := v.Length()
	out := make([]string, n)
	for i := 0; i < n; i++ {
		el := v.Index(i)
		if el.Type() != js.TypeString {
			return nil, fmt.Errorf("element %d is not a string", i)
		}
		out[i] = el.String()
	}
	return out, nil
}

// netBirdClientConstructor acts as a JavaScript constructor function
func netBirdClientConstructor(_ js.Value, args []js.Value) any {
	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		if len(args) < 1 {
			reject.Invoke(js.ValueOf("Options object required"))
			return nil
		}

		go func() {
			options, err := parseClientOptions(args[0])
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			if err := util.InitLog(options.LogLevel, util.LogConsole); err != nil {
				log.Warnf("Failed to initialize logging: %v", err)
			}

			log.Infof("Creating NetBird client with options: deviceName=%s, hasJWT=%v, hasSetupKey=%v, mgmtURL=%s",
				options.DeviceName, options.JWTToken != "", options.SetupKey != "", options.ManagementURL)

			client, err := netbird.New(options)
			if err != nil {
				reject.Invoke(js.ValueOf(fmt.Sprintf("create client: %v", err)))
				return
			}

			clientObj := createClientObject(client)
			log.Info("NetBird client created successfully")
			resolve.Invoke(clientObj)
		}()

		return nil
	}))
}
