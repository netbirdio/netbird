package net

import "errors"

var (
	ErrClosedByServer = errors.New("closed by server")

	// ErrDatagramTooLarge is returned when a transport message exceeds the
	// QUIC datagram size the path to the relay can carry. The relay client
	// treats it as a signal to fall back to a non-datagram transport.
	ErrDatagramTooLarge = errors.New("datagram frame too large")
)
