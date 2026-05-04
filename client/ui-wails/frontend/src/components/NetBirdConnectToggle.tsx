import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/cn";
import netbirdLogo from "@/assets/logos/netbird.svg";

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
    size?: number;
    onClick?: () => void;
};

export const NetBirdConnectToggle = ({ state, size = 140, onClick }: NetBirdConnectToggleProps) => {
    const [visualState, setVisualState] = useState(state);

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

    const padding = size * 0.075;
    const borderGap = 2;
    const borderInset = padding - borderGap;
    const innerSize = size * 0.7;
    const logoSize = size * 0.26;
    const pingInset = size * 0.075;

    return (
        <div>
            <motion.button
                className="rounded-full relative overflow-visible cursor-pointer outline-none border-none bg-transparent"
                style={{ padding }}
                onClick={handleClick}
                whileTap={{ scale: 0.98 }}
                transition={{ type: "spring", stiffness: 400, damping: 17 }}
            >
                <OuterRing state={visualState} />
                <BorderInnerRing state={visualState} inset={borderInset} />
                <InnerRing size={innerSize}>
                    <NetBirdLogo state={visualState} logoSize={logoSize} />
                    <PingRing state={visualState} inset={pingInset} />
                </InnerRing>
            </motion.button>
        </div>
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

const BorderInnerRing = ({ state, inset }: StateProps & { inset: number }) => (
    <div
        className={cn(
            "absolute rounded-full transition-all duration-1000",
            state === ConnectionState.Connected && "bg-netbird-600",
            state === ConnectionState.Disconnecting && "bg-conic-netbird animate-spin-slow",
            state !== ConnectionState.Connected && state !== ConnectionState.Disconnecting && "bg-neutral-500",
        )}
        style={{ inset }}
    />
);

const InnerRing = ({ children, size }: { children: React.ReactNode; size: number }) => (
    <div
        className="rounded-full bg-nb-gray flex items-center justify-center relative z-10 mx-auto"
        style={{ width: size, height: size }}
    >
        {children}
    </div>
);

const NetBirdLogo = ({ state, logoSize }: StateProps & { logoSize: number }) => {
    const isConnecting = state === ConnectionState.Connecting;

    return (
        <div
            className={cn(isConnecting && "animate-pulse-slow")}
            style={isConnecting ? { animationDelay: "0.1s" } : undefined}
        >
            <img
                src={netbirdLogo}
                alt="NetBird"
                width={logoSize}
                className={cn(
                    "filter transition-all duration-1000",
                    state === ConnectionState.Disconnected ? "grayscale" : "grayscale-0",
                )}
            />
        </div>
    );
};

const PingRing = ({ state, inset }: StateProps & { inset: number }) => (
    <span
        className={cn(
            "block absolute border-2 border-netbird rounded-full",
            state === ConnectionState.Connecting ? "animate-ping-slow" : "hidden",
        )}
        style={{ inset }}
    />
);
