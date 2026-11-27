import { useCallback } from "react";
import { useTranslation } from "react-i18next";
import type { RunningConfig } from "@bindings/services/models.js";
import { useStatus } from "@/contexts/StatusContext";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { cn } from "@/lib/cn";

export type RunningConfigField = keyof RunningConfig;

export const usePendingReconnect = () => {
    const { status } = useStatus();
    const { config } = useSettings();
    const running = status?.runningConfig ?? null;

    return useCallback(
        (...fields: RunningConfigField[]) =>
            running !== null && fields.some((f) => running[f] !== config[f]),
        [running, config],
    );
};

export const PendingReconnectNote = ({
    pending,
    className,
}: {
    pending: boolean;
    className?: string;
}) => {
    const { t } = useTranslation();
    if (!pending) return null;
    return (
        <span
            role={"status"}
            className={cn("block text-[.81rem] font-normal text-yellow-400", className)}
        >
            {t("settings.pendingReconnect")}
        </span>
    );
};
