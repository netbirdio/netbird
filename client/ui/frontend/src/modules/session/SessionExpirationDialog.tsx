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
import { EVENT_BROWSER_LOGIN_CANCEL } from "@/lib/connection";
import { errorDialog, formatErrorMessage } from "@/lib/errors.ts";
import { formatRemaining } from "@/lib/formatters";

const DEFAULT_SECONDS = 360;
const WINDOW_WIDTH = 360;
const SOON_THRESHOLD_SECONDS = 60 * 60;

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

    const [remaining, setRemaining] = useState(initialSeconds);
    const [busy, setBusy] = useState(false);
    const busyRef = useRef(busy);
    busyRef.current = busy;
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
    }, [initialSeconds]);

    useEffect(() => {
        const id = globalThis.setInterval(() => {
            setRemaining((s) => (s <= 1 ? 0 : s - 1));
        }, 1000);
        return () => globalThis.clearInterval(id);
    }, [initialSeconds]);

    // Don't auto-close while busy (aborts our WaitExtend) or expired (hides the state).
    useEffect(() => {
        const off = Events.On("netbird:status", (ev: { data: { status?: string } }) => {
            if (busyRef.current || expiredRef.current) return;
            if (ev?.data?.status === "Connected") {
                WindowManager.CloseSessionExpiration().catch(console.error);
            }
        });
        return () => {
            off();
        };
    }, []);

    const stay = useCallback(async () => {
        if (busy) return;
        setBusy(true);

        let offCancel: (() => void) | undefined;

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
                return;
            }

            // Another surface owns this flow; keep the dialog open to retry.
            if (outcome.result.preempted) {
                return;
            }

            // Close before the popup so the restore can't flash this window back.
            WindowManager.CloseSessionExpiration().catch(console.error);
        } catch (e) {
            await errorDialog({
                Title: t("sessionExpiration.extendFailedTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            offCancel?.();
            WindowManager.CloseBrowserLogin().catch(console.error);
            setBusy(false);
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
            await errorDialog({
                Title: t("sessionExpiration.logoutFailedTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
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
                    onClick={stay}
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
