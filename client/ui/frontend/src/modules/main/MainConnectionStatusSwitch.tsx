import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import i18next from "@/lib/i18n";
import { ToggleSwitch } from "@/components/switches/ToggleSwitch.tsx";
import { useStatus } from "@/contexts/StatusContext.tsx";
import { useProfile } from "@/contexts/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { TruncatedText } from "@/components/TruncatedText";
import { shortenDns } from "@/lib/formatters";
import { contentTop } from "@/components/empty-state/EmptyState";
import { Check as CheckIcon, ChevronDownIcon, Copy as CopyIcon } from "lucide-react";
import * as Popover from "@radix-ui/react-popover";
import netbirdFullLogo from "@/assets/logos/netbird-full.svg";

const EVENT_BROWSER_LOGIN_CANCEL = "browser-login:cancel";

const EVENT_TRIGGER_LOGIN = "trigger-login";

let loginInFlight = false;

// onSettled (re-arm guards) must fire before the error dialog, never gated on it:
// a hanging dialog would silently drop every later login until restart.
async function startLogin(onSettled?: () => void): Promise<void> {
    if (loginInFlight) {
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
                waitPromise.catch(() => {});
                return;
            }
        }

        await Connection.Up({ profileName: "", username: "" });
    } catch (e) {
        WindowManager.CloseBrowserLogin().catch(console.error);
        if (!cancelled) loginError = e;
    } finally {
        offCancel?.();
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

const STATUS_KEY: Record<ConnectionState, string> = {
    [ConnectionState.Disconnected]: "connect.status.disconnected",
    [ConnectionState.Connecting]: "connect.status.connecting",
    [ConnectionState.Connected]: "connect.status.connected",
    [ConnectionState.Disconnecting]: "connect.status.disconnecting",
};

const NEEDS_LOGIN_STATES = new Set(["NeedsLogin", "SessionExpired", "LoginFailed"]);

const FORCE_TOGGLE_DELAY_MS = 7000;

const errorMessage = formatErrorMessage;

export const MainConnectionStatusSwitch = () => {
    const { t } = useTranslation();
    const { status, refresh } = useStatus();
    const { activeProfile, username } = useProfile();

    const daemonState = status?.status ?? "Idle";
    const needsLogin = NEEDS_LOGIN_STATES.has(daemonState);
    const unreachable = daemonState === "DaemonUnavailable";

    type Action = "connect" | "logging-in" | "disconnect" | null;
    const [action, setAction] = useState<Action>(null);

    const loginGuard = useRef(false);
    const driveLogin = useCallback(() => {
        if (loginGuard.current) return;
        loginGuard.current = true;
        setAction("logging-in");
        void startLogin(() => {
            loginGuard.current = false;
            setAction(null);
            refresh().catch((err: unknown) => console.error("refresh after login failed", err));
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
    };

    const sawConnectingRef = useRef(false);

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
            Events.Emit(EVENT_BROWSER_LOGIN_CANCEL).catch((err: unknown) =>
                console.error("emit browser-login cancel failed", err),
            );
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
            className={cn("flex flex-col h-full w-full items-center gap-4", "relative")}
            style={{ top: contentTop("11.7rem") }}
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

const IpRow = ({ value }: { value: string }) => {
    const [copied, setCopied] = useState(false);
    const handleClick = async () => {
        if (!value) return;
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 500);
        } catch {}
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
