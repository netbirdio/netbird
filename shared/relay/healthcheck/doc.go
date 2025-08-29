/*
The `healthcheck` package is responsible for managing the health checks between the client and the relay server. It
ensures that the connection between the client and the server are alive and functioning properly.

The `Sender` struct is responsible for sending health check signals to the receiver. The receiver listens for these
signals and sends a new signal back to the sender to acknowledge that the signal has been received. If the sender does
not receive an acknowledgment signal within a certain time frame, it will send a timeout signal via timeout channel
and stop working.

The `Receiver` struct is responsible for receiving the health check signals from the sender. If the receiver does not
receive a signal within a certain time frame, it will send a timeout signal via the OnTimeout channel and stop working.

In the Relay usage the signal is sent to the peer in message type Healthcheck. In case of timeout the connection is
closed and the peer is removed from the relay.
*/

package healthcheck
