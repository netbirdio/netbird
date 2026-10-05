import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { AlertCircleIcon, ClockIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { Connection, Profiles as ProfilesSvc, Session, WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { EVENT_BROWSER_LOGIN_CANCEL, EVENT_TRIGGER_LOGIN } from "@/lib/connection";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";
import { formatRemaining } from "@/lib/formatters";

const DEFAULT_SECONDS = 360;
const WINDOW_WIDTH = 360;
const SOON_THRESHOLD_SECONDS = 60 * 60;
const DEADLINE_TOLERANCE_MS = 5 * 1000;
// The final-warning deadline reaches the Go side as RFC3339 truncated to whole
// seconds, while the status snapshot carries millisecond precision, so an
// unchanged deadline can look up to 999 ms newer than the exact URL value.
const EXACT_DEADLINE_TOLERANCE_MS = 999;

export default function SessionExpirationDialog() {
    const { t } = useTranslation();
    const contentRef = useAutoSizeWindow<HTMLDivElement>(WINDOW_WIDTH);
    const [params] = useSearchParams();
    const initialSeconds = useMemo(() => {
        const raw = params.get("seconds");
        if (!raw) return DEFAULT_SECONDS;
        const n = Number.parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 ? n : DEFAULT_SECONDS;
    }, [params]);
    const initialDeadline = useMemo(() => {
        const raw = params.get("deadline");
        if (!raw) return null;
        const n = Number.parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 ? n : null;
    }, [params]);

    const [remaining, setRemaining] = useState(initialSeconds);
    const [busy, setBusy] = useState(false);
    const busyRef = useRef(busy);
    busyRef.current = busy;
    const openedDeadlineRef = useRef(initialDeadline ?? Date.now() + initialSeconds * 1000);
    const exactDeadlineRef = useRef(initialDeadline !== null);
    const expired = remaining <= 0;
    const expiredRef = useRef(expired);
    expiredRef.current = expired;
    const soon = remaining <= SOON_THRESHOLD_SECONDS;
    const activeTitle = soon ? t("sessionExpiration.title") : t("sessionExpiration.titleLater");
    const activeDescription = soon
        ? t("sessionExpiration.description")
        : t("sessionExpiration.descriptionLater");

    useEffect(() => {
        setRemaining(initialSeconds);
        openedDeadlineRef.current = initialDeadline ?? Date.now() + initialSeconds * 1000;
        exactDeadlineRef.current = initialDeadline !== null;
    }, [initialSeconds, initialDeadline]);

    // Recompute from the absolute deadline instead of decrementing per tick: webview
    // timers get suspended for tens of seconds (App Nap / hidden-window throttling),
    // so a tick counter drifts behind the wall clock by the suspended time.
    useEffect(() => {
        const id = globalThis.setInterval(() => {
            setRemaining(Math.max(0, Math.ceil((openedDeadlineRef.current - Date.now()) / 1000)));
        }, 1000);
        return () => globalThis.clearInterval(id);
    }, [initialSeconds]);

    // Auto-close only when the session was actually renewed elsewhere (tray action, CLI,
    // main window): the daemon keeps emitting Connected snapshots regardless of session
    // state, so the signal is the deadline jumping past the one this dialog was opened for.
    // With the exact deadline from the URL any jump past its sub-second precision loss
    // counts; the seconds-derived fallback needs a wider tolerance for the Go-side
    // truncation and mount latency.
    // Don't auto-close while busy (aborts our WaitExtend) or expired (hides the state).
    useEffect(() => {
        const off = Events.On(
            "netbird:status",
            (ev: { data: { status?: string; sessionExpiresAt?: string | null } }) => {
                if (busyRef.current || expiredRef.current) return;
                if (ev?.data?.status !== "Connected") return;
                const raw = ev?.data?.sessionExpiresAt;
                if (!raw) return;
                const renewed = Date.parse(raw);
                if (!Number.isFinite(renewed)) return;
                const tolerance = exactDeadlineRef.current
                    ? EXACT_DEADLINE_TOLERANCE_MS
                    : DEADLINE_TOLERANCE_MS;
                if (renewed - openedDeadlineRef.current > tolerance) {
                    WindowManager.CloseSessionExpiration().catch(console.error);
                }
            },
        );
        return () => {
            off();
        };
    }, []);

    const stay = useCallback(async () => {
        if (busy) return;
        setBusy(true);

        let offCancel: (() => void) | undefined;

        // Return the dialog to its interactive state and dismiss the browser popup
        const resetDialog = () => {
            offCancel?.();
            WindowManager.CloseBrowserLogin().catch(console.error);
            setBusy(false);
        };

        try {
            const start = await Session.RequestExtend({ hint: "" });
            const uri = start.verificationUriComplete || start.verificationUri;

            // The popup opens the URL and (Go-side) hides this window, restoring it on close.
            if (uri) {
                try {
                    await WindowManager.OpenBrowserLogin(uri);
                } catch (e) {
                    console.error(e);
                }
            }

            const cancelPromise = new Promise<void>((resolve) => {
                offCancel = Events.On(EVENT_BROWSER_LOGIN_CANCEL, () => {
                    resolve();
                });
            });

            const waitPromise = Session.WaitExtend({
                deviceCode: start.deviceCode,
                userCode: start.userCode,
            });

            const outcome = await Promise.race([
                waitPromise.then((r) => ({ kind: "done" as const, result: r })),
                cancelPromise.then(() => ({ kind: "cancel" as const })),
            ]);

            if (outcome.kind === "cancel") {
                waitPromise.cancel?.();
                waitPromise.catch(() => {});
                resetDialog();
                return;
            }

            // Another surface owns this flow; keep the dialog open to retry.
            if (outcome.result.preempted) {
                resetDialog();
                return;
            }
            WindowManager.CloseRenewFlow().catch(console.error);
        } catch (e) {
            resetDialog();
            await errorDialog({
                Title: t("sessionExpiration.extendFailedTitle"),
                Message: formatErrorMessage(e),
            });
        }
    }, [busy, t]);

    const authenticate = useCallback(async () => {
        if (busy) return;
        setBusy(true);
        try {
            await Events.Emit(EVENT_TRIGGER_LOGIN);
            await WindowManager.CloseSessionExpiration();
        } catch (e) {
            setBusy(false);
            await errorDialog({
                Title: t("connect.error.loginTitle"),
                Message: formatErrorMessage(e),
            });
        }
    }, [busy, t]);

    const logout = useCallback(async () => {
        if (busy) return;
        setBusy(true);
        try {
            const username = await ProfilesSvc.Username();
            const active = await ProfilesSvc.GetActive();
            await Connection.Logout({
                profileName: active.id || "default",
                username,
            });
            WindowManager.CloseSessionExpiration().catch(console.error);
        } catch (e) {
            setBusy(false);
            await errorDialog({
                Title: t("sessionExpiration.logoutFailedTitle"),
                Message: formatErrorMessage(e),
            });
        }
    }, [busy, t]);

    const close = useCallback(() => {
        WindowManager.CloseSessionExpiration().catch(console.error);
    }, []);

    return (
        <ConfirmDialog ref={contentRef} aria-labelledby={"nb-session-expiration-title"}>
            <SquareIcon icon={expired ? AlertCircleIcon : ClockIcon} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading id={"nb-session-expiration-title"}>
                    {expired ? t("sessionExpiration.expired") : activeTitle}
                </DialogHeading>
                <DialogDescription>
                    {expired ? t("sessionExpiration.expiredDescription") : activeDescription}
                </DialogDescription>
            </div>

            {!expired && (
                <div
                    className={
                        "font-mono text-2xl font-semibold tabular-nums tracking-wider text-nb-gray-50"
                    }
                    aria-live={"polite"}
                >
                    {formatRemaining(remaining)}
                </div>
            )}

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={expired ? authenticate : stay}
                    disabled={busy}
                >
                    {expired ? t("sessionExpiration.authenticate") : t("sessionExpiration.stay")}
                </Button>
                <Button
                    variant={"secondary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={expired ? close : logout}
                    disabled={busy}
                >
                    {expired ? t("sessionExpiration.close") : t("sessionExpiration.logout")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
