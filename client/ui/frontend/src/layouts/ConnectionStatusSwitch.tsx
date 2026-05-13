import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Dialogs } from "@wailsio/runtime";
import { Connection } from "@bindings/services";
import { ConnectionState } from "@/components/NetBirdConnectToggle.tsx";
import { ToggleSwitch } from "@/components/ToggleSwitch.tsx";
import { useStatus } from "@/hooks/useStatus";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

const STATUS_LABEL: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "Disconnected",
    [ConnectionState.Connecting]: "Connecting...",
    [ConnectionState.Connected]: "Connected",
    [ConnectionState.Disconnecting]: "Disconnecting...",
};

const errorMessage = (e: unknown) =>
    e instanceof Error ? e.message : String(e);

export const ConnectionStatusSwitch = () => {
    const { status, refresh } = useStatus();
    const { activeProfile, username } = useProfile();
    const navigate = useNavigate();

    const daemonState = status?.status ?? "Idle";
    const needsLogin =
        daemonState === "NeedsLogin" ||
        daemonState === "SessionExpired" ||
        daemonState === "LoginFailed";
    const unreachable = daemonState === "DaemonUnavailable";

    // Tracks an in-flight user action (Up/Down RPC + refresh) so we can show a
    // transitional label and disable the switch without lying about the
    // daemon's actual state.
    const [action, setAction] = useState<"connect" | "disconnect" | null>(null);

    const connState: ConnectionState = useMemo(() => {
        if (action === "disconnect" && daemonState === "Connected") {
            return ConnectionState.Disconnecting;
        }
        if (action === "connect" && daemonState !== "Connected") {
            return ConnectionState.Connecting;
        }
        switch (daemonState) {
            case "Connected":
                return ConnectionState.Connected;
            case "Connecting":
                return ConnectionState.Connecting;
            default:
                return ConnectionState.Disconnected;
        }
    }, [daemonState, action]);

    const connect = async () => {
        setAction("connect");
        try {
            await Connection.Up({
                profileName: activeProfile,
                username,
            });
        } catch (e) {
            await Dialogs.Error({
                Title: "Connect Failed",
                Message: errorMessage(e),
            });
        } finally {
            await refresh();
            setAction(null);
        }
    };

    const disconnect = async () => {
        setAction("disconnect");
        try {
            await Connection.Down();
        } catch (e) {
            await Dialogs.Error({
                Title: "Disconnect Failed",
                Message: errorMessage(e),
            });
        } finally {
            await refresh();
            setAction(null);
        }
    };

    const handleSwitch = (next: boolean) => {
        if (unreachable || action !== null) return;
        if (needsLogin) {
            navigate("/login");
            return;
        }
        if (next && connState === ConnectionState.Disconnected) {
            void connect();
        } else if (!next && connState === ConnectionState.Connected) {
            void disconnect();
        }
    };

    const isTransitioning =
        connState === ConnectionState.Connecting ||
        connState === ConnectionState.Disconnecting;
    const isOn =
        connState === ConnectionState.Connected ||
        connState === ConnectionState.Connecting;
    const showLocal = connState === ConnectionState.Connected;
    const fqdn = status?.local.fqdn || "";
    const ip = status?.local.ip || "";

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
                disabled={isTransitioning || unreachable}
                className={cn(
                    unreachable && "opacity-80",
                    isTransitioning && "animate-pulse",
                )}
            />

            <div className={"flex flex-col items-center"}>
                <h1
                    className={
                        "text-sm font-medium text-nb-gray-200 tracking-wide transition-colors duration-300"
                    }
                >
                    {unreachable
                        ? "Daemon unavailable"
                        : needsLogin
                          ? "Login required"
                          : STATUS_LABEL[connState]}
                </h1>
                <p
                    className={cn(
                        "font-mono text-xs leading-tight min-h-[1em] text-nb-gray-300 mt-2 transition-opacity duration-300",
                        showLocal && fqdn ? "opacity-100" : "opacity-0",
                    )}
                >
                    {fqdn || " "}
                </p>
                <p
                    className={cn(
                        "font-mono text-xs leading-tight min-h-[1em] text-nb-gray-300 mt-0.5 transition-opacity duration-300",
                        showLocal && ip ? "opacity-100" : "opacity-0",
                    )}
                >
                    {ip || " "}
                </p>
            </div>
        </div>
    );
};
