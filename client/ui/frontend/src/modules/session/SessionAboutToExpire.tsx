import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { ClockIcon } from "lucide-react";
import { Button } from "@/components/Button";
import {
    Connection,
    Profiles as ProfilesSvc,
    WindowManager,
} from "@bindings/services";

const EVENT_TRIGGER_LOGIN = "trigger-login";
const DEFAULT_SECONDS = 360;

function formatMMSS(seconds: number): string {
    const s = Math.max(0, seconds | 0);
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
}

export default function SessionAboutToExpire() {
    const { t } = useTranslation();
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
        <div
            className={
                "h-screen w-full flex flex-col items-center justify-center text-center px-6 py-8 bg-nb-gray-950"
            }
        >
            <div
                className={
                    "h-12 w-12 rounded-full flex items-center justify-center bg-nb-gray-900 text-netbird mb-4"
                }
            >
                <ClockIcon size={22} />
            </div>
            <h1 className={"text-base font-semibold text-nb-gray-100"}>
                {expired
                    ? t("sessionAboutToExpire.expired")
                    : t("sessionAboutToExpire.title")}
            </h1>
            <p className={"text-xs text-nb-gray-400 mt-1.5 max-w-[20rem] leading-snug"}>
                {t("sessionAboutToExpire.description")}
            </p>
            <div
                className={
                    "mt-5 font-mono text-3xl tabular-nums text-nb-gray-100 tracking-wider"
                }
                aria-live={"polite"}
            >
                {formatMMSS(remaining)}
            </div>
            <div className={"flex gap-2 mt-5 w-full max-w-[18rem]"}>
                <Button
                    variant={"secondary"}
                    size={"xs"}
                    className={"flex-1"}
                    onClick={logout}
                >
                    {t("sessionAboutToExpire.logout")}
                </Button>
                <Button
                    variant={"primary"}
                    size={"xs"}
                    className={"flex-1"}
                    onClick={stay}
                    disabled={expired}
                >
                    {t("sessionAboutToExpire.stay")}
                </Button>
            </div>
        </div>
    );
}
