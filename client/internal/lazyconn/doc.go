/*
Package lazyconn provides mechanisms for managing lazy connections, which activate on demand to optimize resource usage and establish connections efficiently.

## Overview

The package includes a `Manager` component responsible for:
- Managing lazy connections activated on-demand
- Managing inactivity monitors for lazy connections (based on peer disconnection events)
- Maintaining a list of excluded peers that should always have permanent connections
- Handling remote peer connection initiatives based on peer signaling

## Thread-Safe Operations

The `Manager` ensures thread safety across multiple operations, categorized by caller:

- **Engine (single goroutine)**:
  - `AddPeer`: Adds a peer to the connection manager.
  - `RemovePeer`: Removes a peer from the connection manager.
  - `ActivatePeer`: Activates a lazy connection for a peer. This come from Signal client
  - `ExcludePeer`: Marks peers for a permanent connection. Like router peers and other peers that should always have a connection.

- **Connection Dispatcher (any peer routine)**:
  - `onPeerConnected`: Suspend the inactivity monitor for an active peer connection.
  - `onPeerDisconnected`: Starts the inactivity monitor for a disconnected peer.

- **Activity Manager**:
  - `onPeerActivity`: Run peer.Open(context).

- **Inactivity Monitor**:
  - `onPeerInactivityTimedOut`: Close peer connection and restart activity monitor.
*/
package lazyconn
