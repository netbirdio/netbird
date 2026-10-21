// Package udpmux provides a custom implementation of a UDP multiplexer
// that allows multiple logical ICE connections to share a single underlying
// UDP socket. This is based on Pion's ICE library, with modifications for
// NetBird's requirements.
//
// # Background
//
// In WebRTC and NAT traversal scenarios, ICE (Interactive Connectivity
// Establishment) is responsible for discovering candidate network paths
// and maintaining connectivity between peers. Each ICE connection
// normally requires a dedicated UDP socket. However, using one socket
// per candidate can be inefficient and difficult to manage.
//
// This package introduces SingleSocketUDPMux, which allows multiple ICE
// candidate connections (muxed connections) to share a single UDP socket.
// It handles demultiplexing of packets based on ICE ufrag values, STUN
// transaction IDs and attributes, and candidate IDs.
//
// # Usage
//
// The typical flow is:
//
//  1. Create a UDP socket (net.PacketConn).
//  2. Construct Params with the socket and optional logger/net stack.
//  3. Call NewSingleSocketUDPMux(params).
//  4. For each ICE candidate ufrag, call GetConn(ufrag, addr, candidateID)
//     to obtain a logical PacketConn.
//  5. Use the returned PacketConn just like a normal UDP connection.
//
// # STUN Message Routing Logic
//
// When a STUN packet arrives, the mux decides which connection should receive
// it:
//
//   - Responses (success and error) go to the connection that sent the
//     request. Every STUN request a muxed connection writes is recorded by
//     transaction ID, and the record is dropped on the response, when the
//     connection is removed, or after transactionTTL; at most maxTransactions
//     are kept. Host and server reflexive candidates share the socket, so the
//     remote cannot tell which of them sent a check and the candidate pair ID
//     it echoes can name the other one.
//   - Requests and indications go to the connection of the target candidate
//     in the candidate pair ID (ice.CandidatePairIDFromSTUN) when the remote
//     sets one, and otherwise to the host connection of the agent named by the
//     USERNAME ufrag.
//   - A response with an unknown transaction ID is routed by its candidate
//     pair ID.
//   - Anything still unplaced is sent to every connection that has written to
//     the source address, plus the connection matching the USERNAME ufrag.
//
// # Peer Reflexive Candidate Discovery
//
//	When a remote peer sends a STUN message from an unknown source address
//	(from a candidate that has not been exchanged via signal), the ICE
//	library will:
//	  - Generate a new peer reflexive candidate for this source address
//	  - Extract or assign a candidate ID based on the STUN message attributes
//	  - Create a mapping between the new peer reflexive candidate ID and
//	    the appropriate local connection
//
//	This discovery mechanism ensures that STUN messages from newly discovered
//	peer reflexive candidates can be properly routed to the correct local
//	connection without requiring fallback broadcasting.
package udpmux
