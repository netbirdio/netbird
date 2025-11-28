//go:build js

package main

import (
	"context"
	"fmt"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"

	netbird "github.com/netbirdio/netbird/client/embed"
	sshdetection "github.com/netbirdio/netbird/client/ssh/detection"
	"github.com/netbirdio/netbird/client/wasm/internal/http"
	"github.com/netbirdio/netbird/client/wasm/internal/rdp"
	"github.com/netbirdio/netbird/client/wasm/internal/ssh"
	"github.com/netbirdio/netbird/util"
)

const (
	clientStartTimeout         = 30 * time.Second
	clientStopTimeout          = 10 * time.Second
	defaultLogLevel            = "warn"
	defaultSSHDetectionTimeout = 20 * time.Second
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

// createSSHMethod creates the SSH connection method
func createSSHMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			return js.ValueOf("error: requires host and port")
		}

		host := args[0].String()
		port := args[1].Int()
		username := "root"
		if len(args) > 2 && args[2].String() != "" {
			username = args[2].String()
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

// createProxyRequestMethod creates the proxyRequest method
func createProxyRequestMethod(client *netbird.Client) js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 1 {
			return js.ValueOf("error: request details required")
		}

		request := args[0]

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

		proxy := rdp.NewRDCleanPathProxy(client)
		return proxy.CreateProxy(args[0].String(), args[1].String())
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
	obj["detectSSHServerType"] = createDetectSSHServerMethod(client)
	obj["createSSHConnection"] = createSSHMethod(client)
	obj["proxyRequest"] = createProxyRequestMethod(client)
	obj["createRDPProxy"] = createRDPProxyMethod(client)

	return js.ValueOf(obj)
}

// netBirdClientConstructor acts as a JavaScript constructor function
func netBirdClientConstructor(this js.Value, args []js.Value) any {
	return js.Global().Get("Promise").New(js.FuncOf(func(this js.Value, promiseArgs []js.Value) any {
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
