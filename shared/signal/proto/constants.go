package proto

// protocol constants, field names that can be used by both client and server
const HeaderId = "x-wiretrustee-peer-id"
const HeaderRegistered = "x-wiretrustee-peer-registered"

// HeaderRegistrationProbe, sent by a client on ConnectStream, tells Signal that the
// client writes one self-addressed probe on the stream and asks Signal to echo it.
// Proxies such as AWS ALB hold the registration header until that first message.
const HeaderRegistrationProbe = "x-netbird-registration-probe"
