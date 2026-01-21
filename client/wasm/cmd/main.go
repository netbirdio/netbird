//go:build js

package main

import (
	"context"
	"fmt"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	netbird "github.com/netbirdio/netbird/client/embed"
	sshdetection "github.com/netbirdio/netbird/client/ssh/detection"
	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/wasm/internal/http"
	"github.com/netbirdio/netbird/client/wasm/internal/rdp"
	"github.com/netbirdio/netbird/client/wasm/internal/ssh"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"
)

const (
	clientStartTimeout         = 30 * time.Second
	clientStopTimeout          = 10 * time.Second
	pingTimeout                = 10 * time.Second
	defaultLogLevel            = "warn"
	defaultSSHDetectionTimeout = 20 * time.Second

	icmpEchoRequest = 8
	icmpCodeEcho    = 0
	pingBufferSize  = 1500
)

func main() {
	js.Global().Set("NetBirdClient", js.FuncOf(netBirdClientConstructor))

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

		var jwtToken string
		if len(args) > 3 && !args[3].IsNull() && !args[3].IsUndefined() {
			jwtToken = args[3].String()
		}

		return createPromise(func(resolve, reject js.Value) {
			sshClient := ssh.NewClient(client)

			if err := sshClient.Connect(host, port, username, jwtToken); err != nil {
				reject.Invoke(err.Error())
				return
			}

			if err := sshClient.StartSession(80, 24); err != nil {
				if closeErr := sshClient.Close(); closeErr != nil {
					log.Errorf("Error closing SSH client: %v", closeErr)
				}
				reject.Invoke(err.Error())
				return
			}

			jsInterface := ssh.CreateJSInterface(sshClient)
			resolve.Invoke(jsInterface)
		})
	})
}

func performPing(client *netbird.Client, hostname string) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	start := time.Now()
	conn, err := client.Dial(ctx, "ping", hostname)
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
	js.Global().Get("console").Call("log", fmt.Sprintf("Ping to %s: %dms", hostname, latency.Milliseconds()))
}

func performPingTCP(client *netbird.Client, hostname string, port int) {
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	address := fmt.Sprintf("%s:%d", hostname, port)
	start := time.Now()
	conn, err := client.Dial(ctx, "tcp", address)
	if err != nil {
		js.Global().Get("console").Call("log", fmt.Sprintf("TCP ping to %s failed: %v", address, err))
		return
	}
	latency := time.Since(start)

	if err := conn.Close(); err != nil {
		log.Debugf("failed to close TCP connection: %v", err)
	}

	js.Global().Get("console").Call("log", fmt.Sprintf("TCP ping to %s succeeded: %dms", address, latency.Milliseconds()))
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
		return createPromise(func(resolve, reject js.Value) {
			performPing(client, hostname)
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
		return createPromise(func(resolve, reject js.Value) {
			performPingTCP(client, hostname, port)
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

// getStatusOverview is a helper to get the status overview
func getStatusOverview(client *netbird.Client) (nbstatus.OutputOverview, error) {
	fullStatus, err := client.Status()
	if err != nil {
		return nbstatus.OutputOverview{}, err
	}

	pbFullStatus := fullStatus.ToProto()

	return nbstatus.ConvertToStatusOutputOverview(pbFullStatus, false, version.NetbirdVersion(), "", nil, nil, nil, "", ""), nil
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
	obj["status"] = createStatusMethod(client)
	obj["statusSummary"] = createStatusSummaryMethod(client)
	obj["statusDetail"] = createStatusDetailMethod(client)
	obj["getSyncResponse"] = createGetSyncResponseMethod(client)
	obj["setLogLevel"] = createSetLogLevelMethod(client)

	return js.ValueOf(obj)
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
