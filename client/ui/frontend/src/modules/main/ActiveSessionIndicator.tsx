import { useTranslation } from "react-i18next";
import { CircleAlert } from "lucide-react";
import { Tooltip } from "@/components/Tooltip";
import { useStatus } from "@/contexts/StatusContext.tsx";
import { cn } from "@/lib/cn.ts";
import { type ReactNode } from "react";

// ActiveSessionIndicator marks that someone is attached to this machine over
// VNC right now, and warns that disconnecting ends that session — which may be
// the session the person reading it is using.
//
// An alert glyph rather than an info one: this is not neutral context, it is a
// state that changes what the disconnect button does to you.
//
// Only a warning, never a block. Input injected by the VNC agent is
// indistinguishable from local input, so we cannot tell whether this UI is being
// driven remotely, and the owner may want to disconnect on purpose either way.
//
// Renders nothing when no session is attached.
export function ActiveSessionIndicator({ className }: { className?: string }): ReactNode {
    const { t } = useTranslation();
    const { status } = useStatus();
    const sessions = status?.vncSessions ?? [];
    if (sessions.length === 0) return null;

    // The initiator is the dashboard user who started the session, which is more
    // use than a source address. Absent when the session carries no identity.
    const who = sessions
        .map((s) => s.initiator)
        .filter((name): name is string => !!name)
        .join(", ");

    const message = who
        ? t("connect.activeSession.tooltipNamed", { sessionCount: sessions.length, who })
        : t("connect.activeSession.tooltip", { sessionCount: sessions.length });

    return (
        <Tooltip content={<span className={"block max-w-64"}>{message}</span>}>
            <span
                role={"status"}
                aria-label={message}
                className={cn(
                    "inline-flex items-center gap-1 rounded-full border border-yellow-700/50 bg-yellow-900/20 px-2 py-0.5 text-yellow-300",
                    className,
                )}
            >
                <CircleAlert size={12} aria-hidden={true} />
                <span className={"text-[0.7rem] leading-none"}>
                    {t("connect.activeSession.badge")}
                </span>
            </span>
        </Tooltip>
    );
}
