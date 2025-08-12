/*
Package client contains the implementation of the Relay client.

The Relay client is responsible for establishing a connection with the Relay server and sending and receiving messages,
Keep persistent connection with the Relay server and handle the connection issues.
It uses the WebSocket protocol for communication and optionally supports TLS (Transport Layer Security).

If a peer wants to communicate with a peer on a different relay server, the manager will establish a new connection to
the relay server. The connection with these relay servers will be closed if there is no active connection. The peers
negotiate the common relay instance via signaling service.
*/
package client
