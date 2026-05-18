import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { ClockIcon } from "lucide-react";
import { Button } from "@/components/Button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DialogActions } from "@/components/DialogActions";
import { DialogDescription } from "@/components/DialogDescription";
import { DialogHeading } from "@/components/DialogHeading";
import { SquareIcon } from "@/components/SquareIcon";
import { Connection, Profiles as ProfilesSvc, WindowManager } from "@bindings/services";
import { useAutoSizeWindow } from "@/lib/useAutoSizeWindow";

const EVENT_TRIGGER_LOGIN = "trigger-login";
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

    const stay = useCallback(() => {
        void Events.Emit(EVENT_TRIGGER_LOGIN);
        WindowManager.CloseSessionAboutToExpire().catch(console.error);
    }, []);

    const logout = useCallback(async () => {
        try {
            const username = await ProfilesSvc.Username();
            const active = await ProfilesSvc.GetActive();
            await Connection.Logout({
                profileName: active.profileName || "default",
                username,
            });
        } catch (e) {
            console.error("logout from session-about-to-expire failed", e);
        } finally {
            WindowManager.CloseSessionAboutToExpire().catch(console.error);
        }
    }, []);

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
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={stay}
                    disabled={expired}
                >
                    {t("sessionAboutToExpire.stay")}
                </Button>
                <Button
                    variant={"secondary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={logout}
                >
                    {t("sessionAboutToExpire.logout")}
                </Button>
            </DialogActions>
        </ConfirmDialog>
    );
}
