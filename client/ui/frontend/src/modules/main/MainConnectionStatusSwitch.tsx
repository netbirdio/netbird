import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { errorDialog } from "@/lib/dialogs.ts";
import { ToggleSwitch } from "@/components/switches/ToggleSwitch.tsx";
import { useStatus } from "@/contexts/StatusContext.tsx";
import { useProfile } from "@/contexts/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import { formatErrorMessage } from "@/lib/errors.ts";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { TruncatedText } from "@/components/TruncatedText";
import { shortenDns } from "@/lib/formatters";
import { Check as CheckIcon, ChevronDownIcon, Copy as CopyIcon } from "lucide-react";
import * as Popover from "@radix-ui/react-popover";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

// EVENT_BROWSER_LOGIN_CANCEL is emitted by the BrowserLogin window's close
// button (Go side) and by the in-dialog Cancel button. startLogin uses it
// to break the WaitSSOLogin race so the daemon doesn't hang on a stale
// device code.
const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";

// EVENT_TRIGGER_LOGIN lets any window ask the main window's connect-toggle
// to drive a login flow. Mirrors services.EventTriggerLogin on the Go side.
// The tray emits it from menu items so the React UI (which owns the SSO
// orchestration and the browser-login window) takes over.
const EVENT_TRIGGER_LOGIN = "trigger-login";

// loginInFlight is a module-level guard. SSO login involves multiple async
// hops (Login → BrowserLogin window → WaitSSOLogin → Up); a second concurrent
// call would race on the daemon's pending device code and on the popup
// window's singleton, leading to confusing UX. Calls past the first are
// dropped silently — the first invocation owns the flow until it settles.
let loginInFlight = false;

// startLogin drives the daemon's SSO login end-to-end:
//   1. Connection.Login — daemon returns a verification URI if SSO is needed.
//   2. WindowManager.OpenBrowserLogin — show the in-app sign-in popup.
//   3. Race WaitSSOLogin vs the user clicking Cancel.
//   4. On success: Connection.Up.
//   5. On cancel: cancel the in-flight WaitSSOLogin gRPC so the daemon
//      drops the abandoned device code (avoids an Idle blink on the tray).
//
// Errors that aren't user cancellations surface via errorDialog. Concurrent
// calls are dropped via loginInFlight. The BrowserLogin window is closed in
// all exit paths so a stray popup doesn't outlive the flow.
// startLogin drives the SSO flow. onSettled is invoked exactly once, the
// instant the flow itself is over (success, cancel, or error) — BEFORE the
// error dialog is shown. Every guard that gates re-arming the login path
// (the module-level loginInFlight here, and the caller's React-level
// loginGuard via onSettled) must be released at that point, never gated on
// the dialog.
//
// Why the dialog must be outside the guards: the native Windows MessageBox
// disables its parent for its whole lifetime, and the main window's
// WindowClosing hook hides instead of closing — the two race and the dialog
// promise can hang indefinitely (see WAILS-DIALOGS notes). If any guard's
// release awaited the dialog, that guard would stay held for as long as the
// box is open (or forever if it hangs), and every later Connect / tray
// trigger-login would be silently dropped at the guard check until the
// client is restarted. That was the original "can't log in again until
// restart" bug.
async function startLogin(onSettled?: () => void): Promise<void> {
    if (loginInFlight) {
        // The caller's guard must still be released — it was set before this
        // call. Without this the React-level loginGuard would wedge on a
        // dropped concurrent invocation.
        onSettled?.();
        return;
    }
    loginInFlight = true;

    let cancelled = false;
    let offCancel: (() => void) | undefined;
    let loginError: unknown;

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
                waitPromise.cancel?.();
                void waitPromise.catch(() => {});
                return;
            }
        }

        await Connection.Up({ profileName: "", username: "" });
    } catch (e) {
        WindowManager.CloseBrowserLogin().catch(console.error);
        if (!cancelled) loginError = e;
    } finally {
        offCancel?.();
        // Release every guard before any UI work below — never gate re-arming
        // the login path on a dialog that can hang. loginInFlight is ours;
        // onSettled releases the caller's React-level loginGuard.
        loginInFlight = false;
        onSettled?.();
    }

    if (loginError !== undefined) {
        await errorDialog({
            Title: i18next.t("connect.error.loginTitle"),
            Message: formatErrorMessage(loginError),
        });
    }
}

enum ConnectionState {
    Disconnected = "disconnected",
    Connecting = "connecting",
    Connected = "connected",
    Disconnecting = "disconnecting",
}

// NeedsLogin / SessionExpired / DaemonUnavailable never reach this map —
// connState collapses them into Connecting or Disconnected upstream.
const STATUS_KEY: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "connect.status.disconnected",
    [ConnectionState.Connecting]: "connect.status.connecting",
    [ConnectionState.Connected]: "connect.status.connected",
    [ConnectionState.Disconnecting]: "connect.status.disconnecting",
};

const NEEDS_LOGIN_STATES = new Set(["NeedsLogin", "SessionExpired", "LoginFailed"]);

// Re-enable the switch after this long in a transitioning state so the user
// can force a Connection.Down on a stuck Connecting/Disconnecting flow.
const FORCE_TOGGLE_DELAY_MS = 7000;

const errorMessage = formatErrorMessage;

export const MainConnectionStatusSwitch = () => {
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
        // Release the React-level guard via onSettled — fired the instant the
        // flow ends, before startLogin's error dialog. Gating it on the full
        // startLogin() promise would keep loginGuard wedged for the whole
        // dialog lifetime, leaving the tray's trigger-login dropped at the
        // guard check until the client is restarted.
        void startLogin(() => {
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
            await errorDialog({
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
            await errorDialog({
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
        if (unreachable) return;
        if (isTransitioning) {
            if (canForceCancel) void forceCancel();
            return;
        }
        if (action !== null) return;
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

    // When the daemon hangs in Connecting/Disconnecting, give the user an
    // escape hatch: after the delay, the switch becomes clickable again so a
    // tap fires Connection.Down (plus cancels any in-flight SSO flow).
    const [canForceCancel, setCanForceCancel] = useState(false);
    useEffect(() => {
        if (!isTransitioning) {
            setCanForceCancel(false);
            return;
        }
        const id = setTimeout(() => setCanForceCancel(true), FORCE_TOGGLE_DELAY_MS);
        return () => clearTimeout(id);
    }, [isTransitioning]);

    const forceCancel = async () => {
        if (action === "logging-in") {
            void Events.Emit(EVENT_BROWSER_LOGIN_CANCEL);
        }
        WindowManager.CloseBrowserLogin().catch(() => {});
        setAction("disconnect");
        try {
            await Connection.Down();
            await refresh();
        } catch (e) {
            setAction(null);
            await refresh();
            await errorDialog({
                Title: t("connect.error.disconnectTitle"),
                Message: errorMessage(e),
            });
        }
    };
    const show = connState === ConnectionState.Connected;
    const fqdn = status?.local.fqdn || "";
    const ip = status?.local.ip || "";
    const ipv6 = status?.local.ipv6 || "";

    return (
        <div
            className={cn(
                // Anchored from the top so the FQDN/IP lines below the toggle
                // can grow into a popover-aware layout without shifting the
                // toggle itself (justify-center would slide everything up
                // when the IP line is hidden during Disconnected).
                "flex flex-col h-full w-full items-center gap-4",
                "relative top-[11.7rem]",
            )}
        >
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
                disabled={(isTransitioning && !canForceCancel) || unreachable}
                className={cn(unreachable && "opacity-80", isTransitioning && "animate-pulse")}
            />

            <div className={"flex flex-col items-center"}>
                <h1
                    className={
                        "text-sm font-medium text-nb-gray-200 tracking-wide transition-colors duration-300 select-none wails-no-draggable mb-1"
                    }
                >
                    {t(STATUS_KEY[connState])}
                </h1>
                <CopyToClipboard
                    message={fqdn}
                    variant={"bright"}
                    className={cn(
                        "min-h-[1em] transition-opacity duration-300 max-w-full",
                        "relative left-[0.55rem]",
                        show && fqdn ? "opacity-100" : "opacity-0 pointer-events-none",
                    )}
                >
                    <TruncatedText
                        text={shortenDns(fqdn) || " "}
                        className={
                            "block font-mono text-[0.8rem] leading-tight text-nb-gray-300 truncate max-w-[310px]"
                        }
                    />
                </CopyToClipboard>
                <LocalIpLine ip={ip} ipv6={ipv6} show={show} />
            </div>
        </div>
    );
};

// LocalIpLine shows the IPv4 inline (no copy icon). When the peer also has
// an IPv6, a tiny chevron sits next to the IPv4 and clicking the line opens
// a popover containing both v4 and v6, each independently click-to-copy.
const LocalIpLine = ({ ip, ipv6, show }: { ip: string; ipv6: string; show: boolean }) => {
    const [open, setOpen] = useState(false);
    const hasV6 = !!ipv6;

    if (!hasV6) {
        return (
            <CopyToClipboard
                message={ip}
                variant={"bright"}
                className={cn(
                    "min-h-[1em] transition-opacity duration-300",
                    "relative left-[0.55rem]",
                    show && ip ? "opacity-100" : "opacity-0 pointer-events-none",
                )}
            >
                <span className={"font-mono text-[0.8rem] leading-tight text-nb-gray-300"}>
                    {ip || " "}
                </span>
            </CopyToClipboard>
        );
    }

    return (
        <div
            className={cn(
                "min-h-[1em] transition-opacity duration-300 max-w-full",
                "relative wails-no-draggable",
                show && ip ? "opacity-100" : "opacity-0 pointer-events-none",
            )}
        >
            <Popover.Root open={open} onOpenChange={setOpen}>
                <Popover.Trigger asChild>
                    <button
                        type={"button"}
                        className={cn(
                            // relative so the chevron can be absolutely
                            // positioned alongside without widening the trigger
                            // — keeps the IP text centred in its parent and
                            // lets the popover centre cleanly on it.
                            "group relative inline-flex items-center outline-none cursor-default",
                            "transition-colors",
                        )}
                    >
                        <span
                            className={cn(
                                "font-mono text-[0.8rem] leading-tight text-nb-gray-300 transition-colors",
                                "group-hover:text-nb-gray-200",
                                "group-data-[state=open]:text-nb-gray-200",
                            )}
                        >
                            {ip || " "}
                        </span>
                        <ChevronDownIcon
                            size={14}
                            className={cn(
                                "absolute -right-5 top-1/2 -translate-y-1/2",
                                "shrink-0 text-nb-gray-300 transition-colors",
                                "group-hover:text-nb-gray-200",
                                "group-data-[state=open]:text-nb-gray-200",
                            )}
                        />
                    </button>
                </Popover.Trigger>
                <Popover.Portal>
                    <Popover.Content
                        side={"bottom"}
                        align={"center"}
                        sideOffset={6}
                        onOpenAutoFocus={(e) => e.preventDefault()}
                        className={cn(
                            "z-50 min-w-64 max-w-[280px] overflow-hidden",
                            "rounded-lg border border-nb-gray-900 bg-nb-gray-935",
                            "p-1 shadow-lg outline-none text-nb-gray-200",
                            "flex flex-col",
                        )}
                    >
                        <IpRow value={ip} />
                        <div className={"-mx-1 my-1 h-px bg-nb-gray-910"} />
                        <IpRow value={ipv6} />
                    </Popover.Content>
                </Popover.Portal>
            </Popover.Root>
        </div>
    );
};

// IpRow is a single click-to-copy item inside the LocalIpLine popover. Mirrors
// the dropdown-menu item look (rounded, hover bg, transition) and shows a copy
// icon on the right that flips to a checkmark briefly after a successful copy.
const IpRow = ({ value }: { value: string }) => {
    const [copied, setCopied] = useState(false);
    const handleClick = async () => {
        if (!value) return;
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 500);
        } catch {
            // ignore
        }
    };
    return (
        <button
            type={"button"}
            onClick={handleClick}
            className={cn(
                "group/iprow relative flex items-center justify-between gap-3",
                "rounded-md px-2 py-1.5 text-left",
                "text-nb-gray-200 hover:bg-nb-gray-900 hover:text-nb-gray-50",
                "transition-colors outline-none cursor-default",
            )}
        >
            <span className={"font-mono text-[0.75rem] truncate min-w-0"}>{value}</span>
            <span className={"shrink-0 inline-flex items-center text-nb-gray-200"}>
                {copied ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
            </span>
        </button>
    );
};
