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
// attributes, and candidate IDs.
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
//		When a STUN packet arrives, the mux decides which connection should
//		receive it using this routing logic:
//
//		Primary Routing: Candidate Pair ID
//		  - Extract the candidate pair ID from the STUN message using
//		    ice.CandidatePairIDFromSTUN(msg)
//	   - The target candidate is the locally generated candidate that
//	     corresponds to the connection that should handle this STUN message
//		  - If found, use the target candidate ID to lookup the specific
//		    connection in candidateConnMap
//		  - Route the message directly to that connection
//
//		Fallback Routing: Broadcasting
//		  When candidate pair ID is not available or lookup fails:
//		  - Collect connections from addressMap based on source address
//		  - Find connection using username attribute (ufrag) from STUN message
//		  - Remove duplicate connections from the list
//		  - Send the STUN message to all collected connections
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
