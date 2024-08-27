//Package main
/*
The `relay` package contains the implementation of the Relay server and client. The Relay server can be used to relay
messages between peers on a single network channel. In this implementation the transport layer is the WebSocket
protocol.

Between the server and client communication has been design a custom protocol and message format. These messages are
transported over the WebSocket connection. Optionally the server can use TLS to secure the communication.

The service can support multiple Relay server instances. For this purpose the peers must know the server instance URL.
This URL will be sent to the target peer to choose the common Relay server for the communication via Signal service.

*/
package main
