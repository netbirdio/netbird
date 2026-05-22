import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialogs, Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { ToggleSwitch } from "@/components/ToggleSwitch.tsx";
import { useStatus } from "@/modules/daemon-status/StatusContext.tsx";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import { formatErrorMessage } from "@/lib/errors.ts";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

enum ConnectionState {
    Disconnected = "disconnected",
    Connecting = "connecting",
    Connected = "connected",
    Disconnecting = "disconnecting",
}

// Only three user-visible labels: Disconnected, Connecting, Connected.
// Disconnecting maps to "Disconnected" so the optimistic flip on click
// reads as the user's intent (off) rather than naming an intermediate
// state. NeedsLogin / SessionExpired / DaemonUnavailable never reach
// this map — connState collapses them into Connecting or Disconnected
// upstream.
const STATUS_KEY: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "connect.status.disconnected",
    [ConnectionState.Connecting]: "connect.status.connecting",
    [ConnectionState.Connected]: "connect.status.connected",
    [ConnectionState.Disconnecting]: "connect.status.disconnected",
};

const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";
const EVENT_TRIGGER_LOGIN = "trigger-login";

const NEEDS_LOGIN_STATES = new Set(["NeedsLogin", "SessionExpired", "LoginFailed"]);

const errorMessage = formatErrorMessage;

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
                // Open the in-app sign-in popup first; the dialog itself
                // fires Connection.OpenURL after it's actually on screen
                // (see WaitingForBrowserDialog) so the system browser
                // doesn't land on top of a still-hidden NetBird window.
                try {
                    await WindowManager.OpenBrowserLogin(uri);
                } catch (e) {
                    console.error(e);
                }
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
    const needsLogin = NEEDS_LOGIN_STATES.has(daemonState);
    const unreachable = daemonState === "DaemonUnavailable";

    // Tracks an in-flight user action so we can show a transitional label
    // and disable the switch without lying about the daemon's actual state.
    //
    //  "connect"     — user clicked Up; waiting for daemon to settle
    //  "logging-in"  — SSO flow is driving the daemon (Login → browser →
    //                  Up). Keeps the switch in "Connecting" while the
    //                  daemon flaps NeedsLogin → Idle → NeedsLogin →
    //                  Connecting that Login's internal Down causes.
    //  "disconnect"  — user clicked Down; waiting for daemon to settle
    type Action = "connect" | "logging-in" | "disconnect" | null;
    const [action, setAction] = useState<Action>(null);

    // Guards startLogin from being fired twice in parallel (effect path +
    // tray trigger-login + handleSwitch). startLogin's module-level
    // loginInFlight already drops the second daemon call, but its
    // Promise would resolve immediately and the .finally clear our
    // "logging-in" latch while the first flow is still running.
    const loginGuard = useRef(false);
    const driveLogin = useCallback(() => {
        if (loginGuard.current) return;
        loginGuard.current = true;
        setAction("logging-in");
        void startLogin().finally(() => {
            loginGuard.current = false;
            setAction(null);
            void refresh();
        });
    }, [refresh]);

    const connState: ConnectionState = useMemo(() => {
        if (action === "disconnect" && daemonState === "Connected") {
            return ConnectionState.Disconnecting;
        }
        if ((action === "connect" || action === "logging-in") && daemonState !== "Connected") {
            return ConnectionState.Connecting;
        }
        switch (daemonState) {
            case "Connected":
                return ConnectionState.Connected;
            case "Connecting":
                return ConnectionState.Connecting;
            case "Idle":
            case "NeedsLogin":
            case "LoginFailed":
            case "SessionExpired":
            case "DaemonUnavailable":
                // NeedsLogin / SessionExpired without an in-flight user
                // action read as Disconnected — the switch only flips to
                // Connecting once the user (or the tray's trigger-login)
                // kicks off the SSO flow, which sets action = "logging-in"
                // and is handled by the guard above.
                return ConnectionState.Disconnected;
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
            await refresh();
        } catch (e) {
            setAction(null);
            await refresh();
            await Dialogs.Error({
                Title: t("connect.error.connectTitle"),
                Message: errorMessage(e),
            });
        }
        // Don't clear action here on success — the daemon's first status
        // push (Connecting / NeedsLogin / ...) may land after Up returns,
        // and clearing eagerly would let connState fall back to
        // Disconnected for one render. The effect below clears the latch
        // once daemonState catches up.
    };

    const disconnect = async () => {
        setAction("disconnect");
        try {
            await Connection.Down();
            await refresh();
        } catch (e) {
            setAction(null);
            await refresh();
            await Dialogs.Error({
                Title: t("connect.error.disconnectTitle"),
                Message: errorMessage(e),
            });
        }
        // See connect() above — clear via the effect, not eagerly.
    };

    // Tracks whether the daemon has entered Connecting during the
    // current "connect" action. Lets us distinguish "still waiting for
    // the daemon to start" (Idle → Idle) from "the connect flow was
    // cancelled externally" (Connecting → Idle, e.g. tray Disconnect
    // while the UI was Connecting). Reset whenever action returns to
    // null.
    const sawConnectingRef = useRef(false);

    // Release the action latch when the daemon settles on a terminal
    // state for the user's intent — and, in the connect → NeedsLogin
    // case, hand off to driveLogin so the user doesn't have to click
    // the switch a second time. "logging-in" is cleared by driveLogin's
    // .finally, not here: Login's internal Down makes the daemon flap
    // through Idle, which would otherwise look like a terminal state.
    useEffect(() => {
        if (action === null) {
            sawConnectingRef.current = false;
            return;
        }
        if (daemonState === "Connecting") {
            sawConnectingRef.current = true;
        }
        if (action === "connect") {
            if (needsLogin) {
                driveLogin();
                return;
            }
            if (daemonState === "Connected" || unreachable) {
                setAction(null);
                return;
            }
            // Cancelled externally (e.g. tray Disconnect during our
            // Connecting): the daemon went back to Idle after we'd
            // observed Connecting. Clear the latch so the UI stops
            // showing Connecting forever.
            if (sawConnectingRef.current && daemonState === "Idle") {
                setAction(null);
            }
            return;
        }
        if (action === "disconnect") {
            if (daemonState === "Idle" || daemonState === "Disconnected" || unreachable) {
                setAction(null);
            }
        }
    }, [action, daemonState, needsLogin, unreachable, driveLogin]);

    // The tray clicks Connect via its own gRPC call. When the daemon flips
    // to NeedsLogin afterwards, the tray emits trigger-login so the React
    // UI (which owns the SSO orchestration and the browser-login window)
    // takes over. driveLogin's loginGuard handles concurrent tray +
    // switch clicks.
    useEffect(() => {
        const off = Events.On(EVENT_TRIGGER_LOGIN, () => {
            driveLogin();
        });
        return () => off();
    }, [driveLogin]);

    const handleSwitch = (next: boolean) => {
        if (unreachable || action !== null) return;
        if (needsLogin) {
            driveLogin();
            return;
        }
        if (next && connState === ConnectionState.Disconnected) {
            void connect();
        } else if (!next && connState === ConnectionState.Connected) {
            void disconnect();
        }
    };

    const isTransitioning =
        connState === ConnectionState.Connecting || connState === ConnectionState.Disconnecting;
    const isOn =
        connState === ConnectionState.Connected || connState === ConnectionState.Connecting;
    const showLocal = connState === ConnectionState.Connected;
    const fqdn = status?.local.fqdn || "";
    const ip = status?.local.ip || "";

    return (
        <div className={cn("flex flex-col h-full w-full items-center justify-center gap-4 -mt-4")}>
            <img
                src={netbirdFullLogo}
                alt={"NetBird"}
                className={"h-7 w-auto select-none mb-4 wails-no-draggable"}
                draggable={false}
            />

            <ToggleSwitch
                size={"large"}
                checked={isOn}
                onCheckedChange={handleSwitch}
                disabled={isTransitioning || unreachable}
                className={cn(unreachable && "opacity-80", isTransitioning && "animate-pulse")}
            />

            <div className={"flex flex-col items-center"}>
                <h1
                    className={
                        "text-sm font-medium text-nb-gray-200 tracking-wide transition-colors duration-300 select-none wails-no-draggable"
                    }
                >
                    {t(STATUS_KEY[connState])}
                </h1>
                <p
                    className={cn(
                        "font-mono text-xs leading-tight min-h-[1em] text-nb-gray-300 mt-2 transition-opacity duration-300 wails-no-draggable",
                        showLocal && fqdn ? "opacity-100" : "opacity-0",
                    )}
                >
                    {fqdn || " "}
                </p>
                <p
                    className={cn(
                        "font-mono text-xs leading-tight min-h-[1em] text-nb-gray-300 mt-0.5 transition-opacity duration-300 wails-no-draggable",
                        showLocal && ip ? "opacity-100" : "opacity-0",
                    )}
                >
                    {ip || " "}
                </p>
            </div>
        </div>
    );
};
