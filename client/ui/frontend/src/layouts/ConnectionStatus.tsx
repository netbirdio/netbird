import { useEffect, useRef, useState } from "react";
import { ConnectionState, NetBirdConnectToggle } from "@/components/NetBirdConnectToggle.tsx";
import Button from "@/components/Button.tsx";
import { cn } from "@/lib/cn.ts";

const CONNECT_DURATION_MS = 1500;
const DISCONNECT_DURATION_MS = 800;

const STATUS_LABEL: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "Disconnected",
    [ConnectionState.Connecting]: "Connecting...",
    [ConnectionState.Connected]: "Connected",
    [ConnectionState.Disconnecting]: "Disconnecting...",
};

export const ConnectionStatus = () => {
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

    const handleToggleClick = () => {
        if (state === ConnectionState.Disconnected) connect();
        else if (state === ConnectionState.Connected) disconnect();
    };

    const handleButtonClick = () => {
        if (state === ConnectionState.Disconnected) {
            connect();
            return;
        }
        if (state === ConnectionState.Connected) {
            if (timerRef.current) {
                clearTimeout(timerRef.current);
                timerRef.current = null;
            }
            setState(ConnectionState.Disconnected);
        }
    };

    const isTransitioning =
        state === ConnectionState.Connecting || state === ConnectionState.Disconnecting;
    const isConnectedSide =
        state === ConnectionState.Connected || state === ConnectionState.Disconnecting;

    const buttonLabel = isConnectedSide ? "Disconnect" : "Connect";
    const buttonVariant = isConnectedSide ? "secondary" : "primary";

    return (
        <div className={cn("flex flex-col h-full w-full items-center justify-between", "-mt-4")}>
            <div className={"w-full h-full flex flex-col items-center justify-center"}>
                <div className={"flex flex-col items-center justify-center"}>
                    <p
                        className={
                            "font-mono text-xs text-nb-gray-300 transition-opacity duration-300 " +
                            (state === ConnectionState.Connected ? "opacity-100" : "opacity-0")
                        }
                    >
                        peer-hostname.netbird.cloud
                    </p>
                    <p
                        className={
                            "font-mono text-xs text-nb-gray-300 mt-0.5 mb-6 transition-opacity duration-300 " +
                            (state === ConnectionState.Connected ? "opacity-100" : "opacity-0")
                        }
                    >
                        192.168.0.1
                    </p>
                </div>
                <NetBirdConnectToggle state={state} onClick={handleToggleClick} />
                <div
                    className={
                        "flex flex-col w-full items-center justify-center gap-3 p-4 rounded-2xl mt-2"
                    }
                >
                    <h1 className={"text-sm font-medium text-nb-gray-200 tracking-wide"}>
                        {STATUS_LABEL[state]}
                    </h1>
                    <div className={"w-full"}>
                        <Button
                            variant={buttonVariant}
                            size={"xs"}
                            className={"w-full"}
                            disabled={isTransitioning}
                            onClick={handleButtonClick}
                        >
                            {buttonLabel}
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    );
};
