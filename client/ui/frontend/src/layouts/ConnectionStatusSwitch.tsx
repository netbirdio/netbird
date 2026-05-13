import { useEffect, useRef, useState } from "react";
import { ConnectionState } from "@/components/NetBirdConnectToggle.tsx";
import { ToggleSwitch } from "@/components/ToggleSwitch.tsx";
import { cn } from "@/lib/cn.ts";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

const CONNECT_DURATION_MS = 1500;
const DISCONNECT_DURATION_MS = 800;

const STATUS_LABEL: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "Disconnected",
    [ConnectionState.Connecting]: "Connecting...",
    [ConnectionState.Connected]: "Connected",
    [ConnectionState.Disconnecting]: "Disconnecting...",
};

export const ConnectionStatusSwitch = () => {
    const [state, setState] = useState<ConnectionState>(ConnectionState.Disconnected);
    const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(
        () => () => {
            if (timerRef.current) clearTimeout(timerRef.current);
        },
        [],
    );

    const transition = (next: ConnectionState, after: ConnectionState, delay: number) => {
        if (timerRef.current) clearTimeout(timerRef.current);
        setState(next);
        timerRef.current = setTimeout(() => {
            setState(after);
            timerRef.current = null;
        }, delay);
    };

    const connect = () =>
        transition(ConnectionState.Connecting, ConnectionState.Connected, CONNECT_DURATION_MS);
    const disconnect = () =>
        transition(
            ConnectionState.Disconnecting,
            ConnectionState.Disconnected,
            DISCONNECT_DURATION_MS,
        );

    const handleSwitch = (next: boolean) => {
        if (next) {
            if (state === ConnectionState.Disconnected) connect();
        } else if (state === ConnectionState.Connected) {
            disconnect();
        }
    };

    const isTransitioning =
        state === ConnectionState.Connecting || state === ConnectionState.Disconnecting;
    const isOn = state === ConnectionState.Connected || state === ConnectionState.Connecting;

    return (
        <div className={cn("flex flex-col h-full w-full items-center justify-center gap-4 -mt-4")}>
            <img
                src={netbirdFullLogo}
                alt={"NetBird"}
                className={"h-7 w-auto select-none mb-4"}
                draggable={false}
            />

            <ToggleSwitch
                size={"large"}
                checked={isOn}
                onCheckedChange={handleSwitch}
                disabled={isTransitioning}
                className={cn(isTransitioning && "opacity-80")}
            />

            <div className={"flex flex-col items-center"}>
                <h1
                    className={
                        "text-sm font-medium text-nb-gray-200 tracking-wide transition-colors duration-300"
                    }
                >
                    {STATUS_LABEL[state]}
                </h1>
                <p
                    className={
                        "font-mono text-xs text-nb-gray-300 mt-2 transition-opacity duration-300 " +
                        (state === ConnectionState.Connected ? "opacity-100" : "opacity-0")
                    }
                >
                    peer-hostname.netbird.cloud
                </p>
                <p
                    className={
                        "font-mono text-xs text-nb-gray-300 mt-0.5 transition-opacity duration-300 " +
                        (state === ConnectionState.Connected ? "opacity-100" : "opacity-0")
                    }
                >
                    192.168.0.1
                </p>
            </div>
        </div>
    );
};
