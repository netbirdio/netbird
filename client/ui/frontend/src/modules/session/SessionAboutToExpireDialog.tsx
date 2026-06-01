import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { errorDialog } from "@/lib/dialogs.ts";
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
// Below this, the situation is genuinely "soon" and the title/description
// uses the urgent wording. Above it (e.g. opened with hours remaining), the
// "later" variant drops the urgency cue so it doesn't read absurdly.
const SOON_THRESHOLD_SECONDS = 60 * 60;

// Renders the countdown with only the units that matter: mm:ss under an
// hour, hh:mm:ss under a day, dd:hh:mm:ss otherwise. Two-digit zero pad
// throughout so columns don't jump as digits roll over.
function formatRemaining(seconds: number): string {
    const s = Math.max(0, seconds | 0);
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    const pad = (n: number) => String(n).padStart(2, "0");
    if (days > 0) return `${pad(days)}:${pad(hours)}:${pad(minutes)}:${pad(secs)}`;
    if (hours > 0) return `${pad(hours)}:${pad(minutes)}:${pad(secs)}`;
    return `${pad(minutes)}:${pad(secs)}`;
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
    const soon = remaining <= SOON_THRESHOLD_SECONDS;

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
            const result = await Session.WaitExtend({
                deviceCode: start.deviceCode,
                userCode: start.userCode,
            });
            if (result.preempted) {
                // Another UI surface (e.g. the tray "Extend now"
                // notification action) started a flow for the same
                // deadline and took over. Keep the dialog open so the
                // user can re-trigger if the other flow also fails;
                // a successful extend elsewhere refreshes the deadline
                // and this window auto-closes when it's no longer
                // relevant.
                return;
            }
            WindowManager.CloseSessionAboutToExpire().catch(console.error);
        } catch (e) {
            await errorDialog({
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
            await errorDialog({
                Title: t("sessionAboutToExpire.logoutFailedTitle"),
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    }, [busy, t]);

    return (
        <ConfirmDialog ref={contentRef}>
            <SquareIcon icon={ClockIcon} />

            <div className={"flex flex-col items-center gap-1"}>
                <DialogHeading>
                    {expired
                        ? t("sessionAboutToExpire.expired")
                        : soon
                          ? t("sessionAboutToExpire.title")
                          : t("sessionAboutToExpire.titleLater")}
                </DialogHeading>
                <DialogDescription>
                    {soon
                        ? t("sessionAboutToExpire.description")
                        : t("sessionAboutToExpire.descriptionLater")}
                </DialogDescription>
            </div>

            <div
                className={
                    "font-mono font-semibold text-2xl tabular-nums text-nb-gray-50 tracking-wider"
                }
                aria-live={"polite"}
            >
                {formatRemaining(remaining)}
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
