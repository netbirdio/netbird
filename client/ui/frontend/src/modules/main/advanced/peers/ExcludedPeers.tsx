import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { AlertTriangleIcon, ChevronRightIcon } from "lucide-react";
import type { ExcludedPeer } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/Badge";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { TruncatedText } from "@/components/TruncatedText";
import { shortenDns } from "@/lib/formatters";

// Keyed by the reason keys the daemon reports; unrecognized keys render verbatim.
const REASON_KEYS: Record<string, string> = {
    login_expired: "peers.excluded.reason.loginExpired",
    posture_check_failed: "peers.excluded.reason.postureCheckFailed",
    pending_approval: "peers.excluded.reason.pendingApproval",
    edr_non_compliant: "peers.excluded.reason.edrNonCompliant",
    unknown: "peers.excluded.reason.unknown",
};

export const exclusionReasonLabel = (t: TFunction, reason: string): string => {
    const key = REASON_KEYS[reason];
    return key ? t(key) : reason || t("peers.excluded.reason.unknown");
};

type ExcludedPeersBarProps = {
    count: number;
    onView: () => void;
};

export const ExcludedPeersBar = ({ count, onView }: ExcludedPeersBarProps) => {
    const { t } = useTranslation();
    return (
        <button
            type={"button"}
            tabIndex={0}
            onClick={onView}
            className={cn(
                "flex w-full items-center gap-2 px-6 py-3",
                "border-t border-yellow-500/30 bg-yellow-500/10 text-xs font-medium",
                "text-yellow-800 hover:bg-yellow-500/20 dark:text-yellow-200",
                "wails-no-draggable cursor-default text-start outline-hidden transition-colors",
                "focus-visible:ring-2 focus-visible:ring-yellow-500/50 focus-visible:ring-inset",
            )}
        >
            <AlertTriangleIcon size={14} aria-hidden={"true"} className={"shrink-0"} />
            <span className={"min-w-0 flex-1 tabular-nums"}>
                {t("peers.excluded.bar", { count })}
            </span>
            <span className={"flex shrink-0 items-center gap-0.5"}>
                {t("peers.excluded.view")}
                <ChevronRightIcon size={14} aria-hidden={"true"} className={"rtl:-scale-x-100"} />
            </span>
        </button>
    );
};

export const ExcludedPeersDescription = () => {
    const { t } = useTranslation();
    return (
        <p className={"border-b border-nb-gray-910 px-6 py-2.5 text-xs text-nb-gray-400"}>
            {t("peers.excluded.description")}
        </p>
    );
};

type Props = {
    peers: ExcludedPeer[];
    unlisted: number;
};

export const ExcludedPeersList = ({ peers, unlisted }: Props) => {
    const { t } = useTranslation();
    return (
        <div className={"flex flex-col py-2"}>
            <ul className={"flex flex-col"}>
                {peers.map((peer) => (
                    <ExcludedPeerRow key={`${peer.fqdn}|${peer.ip}`} peer={peer} />
                ))}
            </ul>
            {unlisted > 0 && (
                <p className={"px-6 py-3 text-xs text-nb-gray-400"}>
                    {t("peers.excluded.more", { count: unlisted })}
                </p>
            )}
        </div>
    );
};

const ExcludedPeerRow = ({ peer }: { peer: ExcludedPeer }) => {
    const { t } = useTranslation();
    const reason = exclusionReasonLabel(t, peer.reason);
    return (
        <li className={"flex min-w-0 items-start gap-2.5 py-3 ps-6 pe-4"}>
            <div className={"flex min-w-0 flex-1 flex-col leading-tight"}>
                <div>
                    <CopyToClipboard message={peer.fqdn}>
                        <TruncatedText
                            text={shortenDns(peer.fqdn)}
                            className={
                                "block max-w-[300px] truncate text-[0.81rem] font-medium text-nb-gray-100"
                            }
                        />
                    </CopyToClipboard>
                </div>
                <div>
                    <CopyToClipboard message={peer.ip}>
                        <span className={"truncate font-mono text-xs text-nb-gray-400"}>
                            {peer.ip}
                        </span>
                    </CopyToClipboard>
                </div>
            </div>
            <Badge variant={"warning"} className={"self-center"}>
                {reason}
            </Badge>
        </li>
    );
};
