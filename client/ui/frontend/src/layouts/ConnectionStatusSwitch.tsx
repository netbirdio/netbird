import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialogs, Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { ToggleSwitch } from "@/components/ToggleSwitch.tsx";
import { useStatus } from "@/hooks/useStatus";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

enum ConnectionState {
    Disconnected = "disconnected",
    Connecting = "connecting",
    Connected = "connected",
    Disconnecting = "disconnecting",
}

const STATUS_KEY: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "connect.status.disconnected",
    [ConnectionState.Connecting]: "connect.status.connecting",
    [ConnectionState.Connected]: "connect.status.connected",
    [ConnectionState.Disconnecting]: "connect.status.disconnecting",
};

const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";

const errorMessage = (e: unknown) =>
    e instanceof Error ? e.message : String(e);

// startLogin drives the daemon's SSO login end-to-end. The BrowserLogin
// popup window is the only login UI; errors surface as a native
// Dialogs.Error. Concurrent calls are dropped via the inFlight guard.
let loginInFlight = false;
async function startLogin(): Promise<void> {
    if (loginInFlight) return;
    loginInFlight = true;

    let cancelled = false;
    let offCancel: (() => void) | undefined;

    try {
        const result = await Connection.Login({
            profileName: "",
            username: "",
            managementUrl: "",
            setupKey: "",
            preSharedKey: "",
            hostname: "",
            hint: "",
        });

        if (result.needsSsoLogin) {
            const uri = result.verificationUriComplete || result.verificationUri;
            if (uri) {
                Connection.OpenURL(uri).catch(console.error);
                WindowManager.OpenBrowserLogin(uri).catch(console.error);
            }

            const cancelPromise = new Promise<void>((resolve) => {
                offCancel = Events.On(EVENT_BROWSER_LOGIN_CANCEL, () => {
                    cancelled = true;
                    resolve();
                });
            });

            const waitPromise = Connection.WaitSSOLogin({
                userCode: result.userCode,
                hostname: "",
            });

            try {
                await Promise.race([waitPromise, cancelPromise]);
            } finally {
                WindowManager.CloseBrowserLogin().catch(console.error);
            }

            if (cancelled) {
                // Tell the daemon to drop the in-flight WaitSSOLogin so a
                // future Login starts fresh; see services/connection.go:74.
                try {
                    await Connection.Down();
                } catch (e) {
                    console.error(e);
                }
                return;
            }
        }

        await Connection.Up({ profileName: "", username: "" });
    } catch (e) {
        WindowManager.CloseBrowserLogin().catch(console.error);
        if (cancelled) return;
        await Dialogs.Error({
            Title: i18next.t("connect.error.loginTitle"),
            Message: errorMessage(e),
        });
    } finally {
        offCancel?.();
        loginInFlight = false;
    }
}

export const ConnectionStatusSwitch = () => {
    const { t } = useTranslation();
    const { status, refresh } = useStatus();
    const { activeProfile, username } = useProfile();

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
                Title: t("connect.error.connectTitle"),
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
                Title: t("connect.error.disconnectTitle"),
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
            void startLogin().finally(() => refresh());
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
                        ? t("connect.status.daemonUnavailable")
                        : needsLogin
                          ? t("connect.status.loginRequired")
                          : t(STATUS_KEY[connState])}
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
