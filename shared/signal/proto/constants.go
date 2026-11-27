package proto

// protocol constants, field names that can be used by both client and server
const HeaderId = "x-wiretrustee-peer-id"
const HeaderRegistered = "x-wiretrustee-peer-registered"

// HeaderStreamEcho, sent by a client on ConnectStream, asks Signal to echo the
// self-addressed probes the client writes on that stream. Signal confirms with the
// same header in its registration response; an older Signal leaves it out.
const HeaderStreamEcho = "x-netbird-stream-echo"
