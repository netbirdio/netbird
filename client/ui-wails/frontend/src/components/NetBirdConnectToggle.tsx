import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import netbirdLogo from "@/assets/netbird.svg";

export enum ConnectionState {
    Disconnected = "disconnected",
    Connecting = "connecting",
    Connected = "connected",
    Disconnecting = "disconnecting",
}

type StateProps = {
    state: ConnectionState;
};

type NetBirdConnectToggleProps = {
    state: ConnectionState;
    onClick?: () => void;
};

export const NetBirdConnectToggle = ({ state, onClick }: NetBirdConnectToggleProps) => {
    const [visualState, setVisualState] = useState(state);

    // Sync with external state when it reaches a settled value
    useEffect(() => {
        setVisualState(state);
    }, [state]);

    const handleClick = () => {
        if (visualState === ConnectionState.Connected) {
            setVisualState(ConnectionState.Disconnecting);
        } else {
            setVisualState(ConnectionState.Connecting);
        }
        onClick?.();
    };

    return (
        <motion.button
            className="p-3 rounded-full relative overflow-visible cursor-pointer outline-none border-none bg-transparent"
            onClick={handleClick}
            whileTap={{ scale: 0.98 }}
            transition={{ type: "spring", stiffness: 400, damping: 17 }}
        >
            <OuterRing state={visualState} />
            <BorderInnerRing state={visualState} />
            <InnerRing>
                <NetBirdLogo state={visualState} />
                <PingRing state={visualState} />
            </InnerRing>
        </motion.button>
    );
};

const OuterRing = ({ state }: StateProps) => {
    const isActive = state === ConnectionState.Connected || state === ConnectionState.Disconnecting;

    return (
        <div
            className={cn(
                "absolute inset-0 rounded-full transition-all",
                isActive ? "bg-netbird-500/20" : "bg-neutral-700",
                state === ConnectionState.Disconnecting && "animate-pulse-slow",
            )}
        />
    );
};

const BorderInnerRing = ({ state }: StateProps) => (
    <div
        className={cn(
            "absolute rounded-full transition-all duration-1000",
            state === ConnectionState.Connected && "bg-netbird-600",
            state === ConnectionState.Disconnecting && "bg-conic-netbird animate-spin-slow",
            state !== ConnectionState.Connected && state !== ConnectionState.Disconnecting && "bg-neutral-500",
        )}
        style={{ inset: "12px" }}
    />
);

const InnerRing = ({ children }: { children: React.ReactNode }) => (
    <div
        className="h-28 w-28 rounded-full bg-nb-gray flex items-center justify-center relative z-10 m-1"
    >
        {children}
    </div>
);

const NetBirdLogo = ({ state }: StateProps) => {
    const isConnecting = state === ConnectionState.Connecting;

    return (
        <div
            className={cn(isConnecting && "animate-pulse-slow")}
            style={isConnecting ? { animationDelay: "0.1s" } : undefined}
        >
            <img
                src={netbirdLogo}
                alt="NetBird"
                width={42}
                className={cn(
                    "filter transition-all duration-1000",
                    state === ConnectionState.Disconnected ? "grayscale" : "grayscale-0",
                )}
            />
        </div>
    );
};

const PingRing = ({ state }: StateProps) => (
    <span
        className={cn(
            "block absolute inset-3 border-2 border-netbird rounded-full",
            state === ConnectionState.Connecting ? "animate-ping-slow" : "hidden",
        )}
    />
);
