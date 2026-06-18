import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import { Connection, WindowManager } from "@bindings/services";
import { ToggleSwitch } from "@/components/switches/ToggleSwitch.tsx";
import { useStatus } from "@/contexts/StatusContext.tsx";
import { useProfile } from "@/contexts/ProfileContext.tsx";
import { cn } from "@/lib/cn.ts";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";
import {
    startConnection,
    EVENT_BROWSER_LOGIN_CANCEL,
    EVENT_TRIGGER_LOGIN,
} from "@/lib/connection.ts";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { TruncatedText } from "@/components/TruncatedText";
import { shortenDns } from "@/lib/formatters";
import { contentTop } from "@/components/empty-state/EmptyState";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { Check as CheckIcon, ChevronDownIcon, Copy as CopyIcon } from "lucide-react";
import * as Popover from "@radix-ui/react-popover";
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

const NEEDS_LOGIN_STATES = new Set(["NeedsLogin", "SessionExpired", "LoginFailed"]);

const FORCE_TOGGLE_DELAY_MS = 7000;

const errorMessage = formatErrorMessage;

export const MainConnectionStatusSwitch = () => {
    const { t } = useTranslation();
    const { status, refresh } = useStatus();
    const { activeProfileId, username } = useProfile();

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
        void startConnection(() => {
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
                profileName: activeProfileId,
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
        WindowManager.CloseBrowserLogin().catch((err: unknown) =>
            console.warn("close browser-login window failed", err),
        );
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
            className={cn("flex h-full w-full flex-col items-center gap-4", "relative")}
            style={{ top: contentTop("11.7rem") }}
        >
            <img
                src={netbirdFullLogo}
                alt={"NetBird"}
                className={"wails-no-draggable mb-4 h-7 w-auto select-none"}
                draggable={false}
            />

            <ToggleSwitch
                size={"large"}
                checked={isOn}
                onCheckedChange={handleSwitch}
                disabled={(isTransitioning && !canForceCancel) || unreachable}
                aria-label={t("connect.toggle.label")}
                aria-describedby={"nb-connection-status"}
                aria-busy={isTransitioning}
                className={cn(unreachable && "opacity-80", isTransitioning && "animate-pulse")}
            />

            <div className={"flex flex-col items-center"}>
                <p
                    id={"nb-connection-status"}
                    role={"status"}
                    aria-live={"polite"}
                    className={
                        "wails-no-draggable mb-1 select-none text-sm font-medium tracking-wide text-nb-gray-200 transition-colors duration-300"
                    }
                >
                    {t(STATUS_KEY[connState])}
                </p>
                <CopyToClipboard
                    message={fqdn}
                    variant={"bright"}
                    iconClassName={"-top-px"}
                    tabIndex={show && fqdn ? 0 : -1}
                    className={cn(
                        "mt-1 max-h-[1em] min-h-[1em] max-w-full transition-opacity duration-300",
                        "relative left-[0.55rem]",
                        show && fqdn ? "opacity-100" : "pointer-events-none opacity-0",
                    )}
                >
                    <TruncatedText
                        text={shortenDns(fqdn) || " "}
                        className={
                            "block h-[18px] max-w-[310px] truncate font-mono text-[0.8rem] leading-tight text-nb-gray-300"
                        }
                    />
                </CopyToClipboard>
                <LocalIpLine ip={ip} ipv6={ipv6} show={show} />
            </div>
        </div>
    );
};

const LocalIpLine = ({ ip, ipv6, show }: { ip: string; ipv6: string; show: boolean }) => {
    const { t } = useTranslation();
    const [open, setOpen] = useState(false);
    const isFocusVisible = useFocusVisible();
    const hasV6 = !!ipv6;

    if (!hasV6) {
        return (
            <CopyToClipboard
                message={ip}
                variant={"bright"}
                tabIndex={show && ip ? 0 : -1}
                className={cn(
                    "mt-1 max-h-[1em] min-h-[1em] transition-opacity duration-300",
                    "relative left-[0.55rem]",
                    show && ip ? "opacity-100" : "pointer-events-none opacity-0",
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
                "min-h-[1em] max-w-full transition-opacity duration-300",
                "wails-no-draggable relative",
                show && ip ? "opacity-100" : "pointer-events-none opacity-0",
            )}
        >
            <Popover.Root open={open} onOpenChange={setOpen}>
                <Popover.Trigger asChild>
                    <button
                        type={"button"}
                        tabIndex={show && ip ? 0 : -1}
                        aria-label={t("connect.localIp.label")}
                        aria-haspopup={"dialog"}
                        aria-expanded={open}
                        className={cn(
                            "group relative inline-flex cursor-default items-center rounded-sm outline-none",
                            isFocusVisible &&
                                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
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
                            aria-hidden={"true"}
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
                            "p-1 text-nb-gray-200 shadow-lg outline-none",
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
    const { t } = useTranslation();
    const [copied, setCopied] = useState(false);
    const isFocusVisible = useFocusVisible();
    const handleClick = async () => {
        if (!value) return;
        try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 500);
        } catch (e) {
            console.warn("copy IP to clipboard failed", e);
        }
    };
    return (
        <button
            type={"button"}
            onClick={handleClick}
            tabIndex={0}
            aria-label={`${t("common.copy")} ${value}`}
            className={cn(
                "group/iprow relative flex items-center justify-between gap-3",
                "rounded-md px-2 py-1.5 text-left",
                "text-nb-gray-200 hover:bg-nb-gray-900 hover:text-nb-gray-50",
                "cursor-default outline-none transition-colors",
                isFocusVisible &&
                    "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
            )}
        >
            <span className={"min-w-0 truncate font-mono text-[0.75rem]"}>{value}</span>
            <span
                aria-hidden={"true"}
                className={"inline-flex shrink-0 items-center text-nb-gray-200"}
            >
                {copied ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
            </span>
        </button>
    );
};
