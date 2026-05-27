import { ComponentType, ReactNode } from "react";
import { useTranslation } from "react-i18next";
import {
    ArrowDownIcon,
    ArrowUpDownIcon,
    ArrowUpIcon,
    CableIcon,
    ClockIcon,
    GaugeIcon,
    HandshakeIcon,
    KeyRoundIcon,
    Layers3Icon,
    LucideProps,
    MapPinIcon,
    MonitorIcon,
    NetworkIcon,
    Radio,
    ZapIcon,
} from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { formatBytes, formatRelative, latencyColor } from "./format";

type Props = {
    peer: PeerStatus;
};

const DASH = "-";

export const PeerDetails = ({ peer }: Props) => {
    const { t } = useTranslation();
    const lastHandshake = formatRelative(peer.lastHandshakeUnix) ?? t("peers.details.never");
    const statusSince = formatRelative(peer.connStatusUpdateUnix) ?? DASH;
    const isConnected = peer.connStatus === "Connected";
    const ConnectionIcon = peer.relayed ? NetworkIcon : ZapIcon;
    const connectionLabel = peer.relayed ? t("peers.details.relayed") : t("peers.details.p2p");

    return (
        <ul className={"flex flex-col divide-y divide-nb-gray-920"}>
            <Row icon={MapPinIcon} label={t("peers.details.netbirdIp")}>
                {peer.ip ? (
                    <CopyToClipboard
                        message={peer.ip}
                        alwaysShowIcon
                        className={"max-w-full"}
                        iconClassName={"top-0"}
                    >
                        <span className={"font-mono"}>{peer.ip}</span>
                    </CopyToClipboard>
                ) : (
                    DASH
                )}
            </Row>
            {isConnected && (
                <Row icon={CableIcon} label={t("peers.details.connection")}>
                    <span className={"inline-flex items-center gap-1.5 whitespace-nowrap"}>
                        <ConnectionIcon size={13} />
                        {connectionLabel}
                    </span>
                </Row>
            )}
            {peer.latencyMs > 0 && (
                <Row icon={GaugeIcon} label={t("peers.details.latency")}>
                    <span className={cn("tabular-nums", latencyColor(peer.latencyMs))}>
                        {peer.latencyMs} ms
                    </span>
                </Row>
            )}
            {(peer.bytesRx > 0 || peer.bytesTx > 0) && (
                <Row icon={ArrowUpDownIcon} label={t("peers.details.bytes")}>
                    <div
                        className={
                            "flex items-center gap-3 justify-end text-nb-gray-300 font-medium"
                        }
                    >
                        <div className={"flex gap-1.5 items-center whitespace-nowrap"}>
                            <ArrowDownIcon size={13} className={"text-sky-400"} />
                            <span className={"sr-only"}>{t("peers.details.bytesReceived")}:</span>
                            <span className={"tabular-nums"}>{formatBytes(peer.bytesRx)}</span>
                        </div>
                        <div className={"flex gap-1.5 items-center whitespace-nowrap"}>
                            <ArrowUpIcon size={13} className={"text-netbird"} />
                            <span className={"sr-only"}>{t("peers.details.bytesSent")}:</span>
                            <span className={"tabular-nums"}>{formatBytes(peer.bytesTx)}</span>
                        </div>
                    </div>
                </Row>
            )}
            <Row icon={HandshakeIcon} label={t("peers.details.lastHandshake")}>
                {lastHandshake}
            </Row>
            <Row icon={ClockIcon} label={t("peers.details.statusSince")}>
                {statusSince}
            </Row>
            <IceRow
                icon={MonitorIcon}
                baseLabel={t("peers.details.localIce")}
                type={peer.localIceCandidateType}
                endpoint={peer.localIceCandidateEndpoint}
            />
            <IceRow
                icon={Radio}
                baseLabel={t("peers.details.remoteIce")}
                type={peer.remoteIceCandidateType}
                endpoint={peer.remoteIceCandidateEndpoint}
            />
            {peer.relayed && (
                <Row icon={NetworkIcon} label={t("peers.details.relayAddress")}>
                    {peer.relayAddress ? (
                        <CopyToClipboard
                            message={peer.relayAddress}
                            alwaysShowIcon
                            className={"max-w-full"}
                            iconClassName={"top-0"}
                        >
                            <span className={"font-mono truncate"}>{peer.relayAddress}</span>
                        </CopyToClipboard>
                    ) : (
                        DASH
                    )}
                </Row>
            )}
            {peer.networks.length > 0 && (
                <Row icon={Layers3Icon} label={t("peers.details.networks")}>
                    <span className={"break-words"}>{peer.networks.join(", ")}</span>
                </Row>
            )}
            <Row icon={KeyRoundIcon} label={t("peers.details.publicKey")}>
                {peer.pubKey ? (
                    <CopyToClipboard
                        message={peer.pubKey}
                        alwaysShowIcon
                        className={"max-w-full"}
                        iconClassName={"top-0"}
                    >
                        <span className={"font-mono truncate"}>{peer.pubKey}</span>
                    </CopyToClipboard>
                ) : (
                    DASH
                )}
            </Row>
        </ul>
    );
};

type RowProps = {
    icon: ComponentType<LucideProps>;
    iconClassName?: string;
    label: string;
    children: ReactNode;
};

type IceRowProps = {
    icon: ComponentType<LucideProps>;
    baseLabel: string;
    type: string;
    endpoint: string;
};

const capitalize = (s: string): string => (s ? s[0].toUpperCase() + s.slice(1) : s);

const IceRow = ({ icon, baseLabel, type, endpoint }: IceRowProps) => {
    if (!type && !endpoint) return null;
    const label = type ? `${baseLabel} (${capitalize(type)})` : baseLabel;
    return (
        <Row icon={icon} label={label}>
            {endpoint ? (
                <CopyToClipboard
                    message={endpoint}
                    alwaysShowIcon
                    className={"max-w-full"}
                    iconClassName={"top-0"}
                >
                    <span className={"font-mono truncate"}>{endpoint}</span>
                </CopyToClipboard>
            ) : (
                <span className={"truncate"}>{capitalize(type)}</span>
            )}
        </Row>
    );
};

const Row = ({ icon: Icon, iconClassName, label, children }: RowProps) => (
    <li className={"flex items-center gap-2 px-5 py-4 text-xs text-nb-gray-100 min-w-0"}>
        <Icon size={14} className={cn("text-nb-gray-100 shrink-0", iconClassName)} />
        <span className={"text-nb-gray-200 shrink-0 font-semibold"}>{label}</span>
        <span
            className={cn(
                "min-w-0 flex-1 text-right pl-8",
                "text-nb-gray-350 font-medium",
                "flex justify-end items-center",
            )}
        >
            {children}
        </span>
    </li>
);
