/*
This package uses a similar HMAC method for authentication with the TURN server. The Management server provides the
tokens for the peers. The peers manage these tokens in the token store. The token store is a simple thread safe store
that keeps the tokens in memory. These tokens are used to authenticate the peers with the Relay server in the hello
message.
*/

package hmac
