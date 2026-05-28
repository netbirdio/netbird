import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Dialogs } from "@wailsio/runtime";
import { ClockIcon } from "lucide-react";
import { Button } from "@/components/buttons/Button";
import { ConfirmDialog } from "@/components/dialog/ConfirmDialog";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import {
    Connection,
    Profiles as ProfilesSvc,
    Session,
    WindowManager,
} from "@bindings/services";
import { useAutoSizeWindow } from "@/hooks/useAutoSizeWindow";
import { formatErrorMessage } from "@/lib/errors.ts";

const DEFAULT_SECONDS = 360;
const WINDOW_WIDTH = 360;

function formatMMSS(seconds: number): string {
    const s = Math.max(0, seconds | 0);
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

export default function SessionAboutToExpireDialog() {
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
    const expired = remaining <= 0;

    useEffect(() => {
        setRemaining(initialSeconds);
    }, [initialSeconds]);

    useEffect(() => {
        if (remaining <= 0) return;
        const id = window.setInterval(() => {
            setRemaining((s) => (s <= 1 ? 0 : s - 1));
        }, 1000);
        return () => window.clearInterval(id);
    }, [remaining]);

    // Mirrors tray.go::runExtendSession: starts the daemon SSO extend flow,
    // opens the browser for the user to sign in, blocks on the daemon until
    // the new deadline arrives. Tunnel stays up; success simply closes the
    // dialog, failure surfaces a native error dialog and leaves this one
    // open so the user can retry or logout.
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
            await Session.WaitExtend({
                deviceCode: start.deviceCode,
                userCode: start.userCode,
            });
            WindowManager.CloseSessionAboutToExpire().catch(console.error);
        } catch (e) {
            await Dialogs.Error({
                Title: t("sessionAboutToExpire.extendFailedTitle"),
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
            WindowManager.CloseSessionAboutToExpire().catch(console.error);
        } catch (e) {
            await Dialogs.Error({
                Title: t("sessionAboutToExpire.logoutFailedTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    }, [busy, t]);

    return (
        <ConfirmDialog ref={contentRef}>
            <SquareIcon icon={ClockIcon} className={"mt-4"} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading>
                    {expired
                        ? t("sessionAboutToExpire.expired")
                        : t("sessionAboutToExpire.title")}
                </DialogHeading>
                <DialogDescription>
                    {t("sessionAboutToExpire.description")}
                </DialogDescription>
            </div>

            <div
                className={
                    "font-mono font-semibold text-2xl tabular-nums text-nb-gray-50 tracking-wider"
                }
                aria-live={"polite"}
            >
                {formatMMSS(remaining)}
            </div>

            <DialogActions>
                <Button
                    autoFocus
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={stay}
                    disabled={expired || busy}
                >
                    {t("sessionAboutToExpire.stay")}
                </Button>
                <Button
                    variant={"secondary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={logout}
                    disabled={busy}
                >
                    {t("sessionAboutToExpire.logout")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
