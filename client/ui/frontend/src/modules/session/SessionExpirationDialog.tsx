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

    // Suppressed while `busy`: the tunnel stays up so Connected re-fires for
    // unrelated reasons (peer/route changes), and closing would abort our own WaitExtend.
    useEffect(() => {
        const off = Events.On("netbird:status", (ev: { data: { status?: string } }) => {
            if (!busyRef.current && ev?.data?.status === "Connected") {
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
        try {
            const start = await Session.RequestExtend({ hint: "" });
            const uri = start.verificationUriComplete || start.verificationUri;
            if (uri) {
                try {
                    await Connection.OpenURL(uri);
                } catch (e) {
                    console.debug("OpenURL failed during extend", e);
                }
            }
            const result = await Session.WaitExtend({
                deviceCode: start.deviceCode,
                userCode: start.userCode,
            });
            if (result.preempted) {
                // Another surface took over this deadline's flow; keep the dialog
                // open to retry. A successful extend elsewhere auto-closes this window.
                return;
            }
            WindowManager.CloseSessionExpiration().catch(console.error);
        } catch (e) {
            await errorDialog({
                Title: t("sessionExpiration.extendFailedTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
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
                profileName: active.profileName || "default",
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
        <ConfirmDialog ref={contentRef}>
            <SquareIcon icon={expired ? AlertCircleIcon : ClockIcon} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading>
                    {expired ? t("sessionExpiration.expired") : activeTitle}
                </DialogHeading>
                <DialogDescription>
                    {expired ? t("sessionExpiration.expiredDescription") : activeDescription}
                </DialogDescription>
            </div>

            {!expired && (
                <div
                    className={
                        "font-mono font-semibold text-2xl tabular-nums text-nb-gray-50 tracking-wider"
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
