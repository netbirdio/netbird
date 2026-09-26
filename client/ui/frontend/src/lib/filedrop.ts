export const enum TransferState {
    Pending = 0,
    Transferring = 1,
    Completed = 2,
    Declined = 3,
    Expired = 4,
    Cancelled = 5,
    Failed = 6,
}

export const enum ReceiveMode {
    Off = 0,
    Ask = 1,
    Auto = 2,
}

export const enum PeerRule {
    Default = 0,
    Always = 1,
    Block = 2,
}

export const enum FailureReason {
    None = 0,
    Unreachable = 1,
}

export const isTerminalState = (state: number): boolean => state >= TransferState.Completed;

export const stateLabelKey = (state: number): string => {
    switch (state) {
        case TransferState.Pending:
            return "files.state.pending";
        case TransferState.Transferring:
            return "files.state.transferring";
        case TransferState.Completed:
            return "files.state.received";
        case TransferState.Declined:
            return "files.state.declined";
        case TransferState.Expired:
            return "files.state.expired";
        case TransferState.Cancelled:
            return "files.state.cancelled";
        default:
            return "files.state.failed";
    }
};
