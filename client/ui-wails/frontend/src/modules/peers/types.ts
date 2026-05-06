export type PeerStatus = "connected" | "connecting" | "disconnected";

export type IceCandidateType = "host" | "srflx" | "relay" | "prflx";

export type Peer = {
    id: string;
    fqdn: string;
    ip: string;
    status: PeerStatus;
    lastHandshake: Date;
    latencyMs: number;
    relayed: boolean;
    relayAddress?: string;
    iceLocalCandidate: IceCandidateType;
    iceRemoteCandidate: IceCandidateType;
    bytesRx: number;
    bytesTx: number;
    endpointLocal: string;
    endpointRemote: string;
};
