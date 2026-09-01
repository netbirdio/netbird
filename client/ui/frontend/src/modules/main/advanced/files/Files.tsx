import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Events } from "@wailsio/runtime";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import {
    ArrowDownIcon,
    ArrowUpIcon,
    BanIcon,
    CheckIcon,
    ChevronDownIcon,
    CopyIcon,
    FolderDownIcon,
    FolderOpenIcon,
    MoreVerticalIcon,
    SendIcon,
    ShieldCheckIcon,
    Trash2Icon,
    XIcon,
} from "lucide-react";
import { FileDrop } from "@bindings/services";
import type { FileDropTransfer, PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { formatBytes } from "@/lib/formatters";
import {
    FailureReason,
    isTerminalState,
    PeerRule,
    stateLabelKey,
    TransferState,
} from "@/lib/filedrop";
import { SearchInput } from "@/components/inputs/SearchInput";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { Button } from "@/components/buttons/Button";
import { Tooltip } from "@/components/Tooltip";
import { TruncatedText } from "@/components/TruncatedText";
import { useConfirm } from "@/contexts/DialogContext";
import { SendPeerPicker } from "@/modules/main/advanced/files/SendPeerPicker";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";

const EVENT_FILEDROP = "netbird:filedrop";
const POLL_MS = 1000;

const transferTitle = (transfer: FileDropTransfer): string => {
    const files = transfer.files ?? [];
    if (files.length === 1 && files[0].isText) {
        return `“${files[0].text}”`;
    }
    return files.map((f) => f.name).join(", ");
};

const isTextTransfer = (transfer: FileDropTransfer): boolean =>
    (transfer.files ?? []).length === 1 && transfer.files[0].isText;

const timeLabel = (iso: string): string => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

// Colours only what the eye should catch scanning the outcome column: a refusal
// or failure in red, a completed send in green. Everything else, a received file
// included, stays neutral so the exceptions stand out.
const outcomeClass = (transfer: FileDropTransfer, inProgress: boolean): string => {
    if (inProgress) return "text-nb-gray-500";
    switch (transfer.state) {
        case TransferState.Declined:
        case TransferState.Failed:
            return "text-red-400";
        case TransferState.Completed:
            return transfer.outgoing ? "text-green-400" : "text-nb-gray-500";
        default:
            return "text-nb-gray-500";
    }
};

export const Files = () => {
    const { t } = useTranslation();
    const [transfers, setTransfers] = useState<FileDropTransfer[] | null>(null);
    const [search, setSearch] = useState("");
    const searchRef = useRef<HTMLInputElement>(null);

    const refresh = useCallback(async () => {
        try {
            setTransfers(await FileDrop.List());
        } catch {
            setTransfers((prev) => prev ?? []);
        }
    }, []);

    useEffect(() => {
        searchRef.current?.focus();
        void refresh();
        const id = setInterval(() => void refresh(), POLL_MS);
        const off = Events.On(EVENT_FILEDROP, () => void refresh());
        return () => {
            clearInterval(id);
            off();
        };
    }, [refresh]);

    const filtered = useMemo(() => {
        const all = transfers ?? [];
        const q = search.trim().toLowerCase();
        if (!q) return all;
        return all.filter(
            (tr) =>
                transferTitle(tr).toLowerCase().includes(q) ||
                tr.peerName.toLowerCase().includes(q),
        );
    }, [transfers, search]);

    const pending = filtered.filter((tr) => !tr.outgoing && tr.state === TransferState.Pending);
    const rest = filtered.filter((tr) => tr.outgoing || tr.state !== TransferState.Pending);

    const groups = useMemo(() => {
        const byDay = new Map<string, FileDropTransfer[]>();
        for (const tr of rest) {
            const d = new Date(tr.createdAt as unknown as string);
            const key = Number.isNaN(d.getTime()) ? "" : d.toDateString();
            const list = byDay.get(key) ?? [];
            list.push(tr);
            byDay.set(key, list);
        }
        const today = new Date().toDateString();
        const yesterday = new Date(Date.now() - 86400000).toDateString();
        return Array.from(byDay.entries()).map(([key, list]) => {
            let label = key;
            if (key === today) label = t("files.group.today");
            else if (key === yesterday) label = t("files.group.yesterday");
            else if (key) label = new Date(key).toLocaleDateString();
            return { label, list };
        });
    }, [rest, t]);

    const isEmpty = transfers !== null && transfers.length === 0;

    return (
        <div className={"flex h-full min-h-0 w-full flex-col"}>
            <div className={"flex items-center gap-2 border-b border-nb-gray-910 px-6 py-2.5"}>
                <div className={"min-w-0 flex-1"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("files.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
                <SendActions onSent={refresh} />
            </div>
            {isEmpty ? (
                <EmptyState
                    icon={FolderDownIcon}
                    title={t("files.empty.title")}
                    description={t("files.empty.description")}
                />
            ) : filtered.length === 0 ? (
                <NoResults />
            ) : (
                <ScrollArea.Root
                    type={"auto"}
                    className={"nb-scroll-clamp min-h-0 flex-1 overflow-hidden"}
                >
                    <ScrollArea.Viewport className={"h-full w-full"}>
                        <div className={"flex flex-col pb-4 pt-2"}>
                            {pending.map((tr) => (
                                <PendingOfferRow key={tr.id} transfer={tr} onChanged={refresh} />
                            ))}
                            {groups.map((group) => (
                                <div key={group.label} className={"flex flex-col"}>
                                    <div
                                        className={
                                            "px-6 pb-1 pt-4 text-xs font-semibold uppercase tracking-wider text-nb-gray-500"
                                        }
                                    >
                                        {group.label}
                                    </div>
                                    {group.list.map((tr) => (
                                        <TransferRow
                                            key={tr.id}
                                            transfer={tr}
                                            onChanged={refresh}
                                        />
                                    ))}
                                </div>
                            ))}
                        </div>
                    </ScrollArea.Viewport>
                    <ScrollArea.Scrollbar
                        orientation={"vertical"}
                        className={"flex w-1.5 touch-none select-none bg-transparent py-1"}
                    >
                        <ScrollArea.Thumb
                            className={
                                "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                            }
                        />
                    </ScrollArea.Scrollbar>
                </ScrollArea.Root>
            )}
        </div>
    );
};

const SendActions = ({ onSent }: { onSent: () => void }) => {
    const { t } = useTranslation();
    const [error, setError] = useState<string | null>(null);

    const sendFiles = async (peer: PeerStatus) => {
        setError(null);
        try {
            const paths = await FileDrop.PickFiles();
            if (!paths || paths.length === 0) return;
            await FileDrop.Send(peer.pubKey, paths, "");
            onSent();
        } catch (e) {
            setError(String(e));
        }
    };

    // Sends the text the picker previewed, not a fresh read: the clipboard may
    // have changed between showing it and confirming the recipient.
    const sendClipboard = async (peer: PeerStatus, text: string) => {
        setError(null);
        if (!text) {
            setError(t("peers.details.sendClipboard.empty"));
            return;
        }
        try {
            await FileDrop.Send(peer.pubKey, [], text);
            onSent();
        } catch (e) {
            setError(String(e));
        }
    };

    return (
        <div className={"relative flex shrink-0 items-center"}>
            <SendPeerPicker
                onPick={(peer, mode, clipboard) =>
                    void (mode === "files" ? sendFiles(peer) : sendClipboard(peer, clipboard))
                }
            >
                <Button variant={"primary"} size={"xs"}>
                    <SendIcon size={12} aria-hidden={"true"} />
                    {t("files.send.trigger")}
                    <ChevronDownIcon size={12} aria-hidden={"true"} />
                </Button>
            </SendPeerPicker>
            {error && (
                <div
                    className={
                        "absolute right-0 top-full z-10 mt-1 max-w-xs truncate text-xs text-red-400"
                    }
                >
                    {error}
                </div>
            )}
        </div>
    );
};

type RowProps = {
    transfer: FileDropTransfer;
    onChanged: () => void;
};

const PendingOfferRow = ({ transfer, onChanged }: RowProps) => {
    const { t } = useTranslation();
    const [busy, setBusy] = useState(false);

    const decide = async (accept: boolean) => {
        if (busy) return;
        setBusy(true);
        try {
            await FileDrop.Decide(transfer.id, accept);
        } finally {
            setBusy(false);
            onChanged();
        }
    };

    return (
        // The panel is a fixed ~500px wide, so the buttons sit under the text
        // rather than beside it: side by side they would squeeze the file name
        // down to a few characters.
        <div
            className={cn(
                "mx-4 mt-2 flex flex-col gap-2.5 rounded-lg border border-netbird/30",
                "bg-netbird/5 px-4 py-3",
                "wails-no-draggable",
            )}
        >
            <div className={"flex min-w-0 items-center gap-2.5"}>
                <ArrowDownIcon size={16} className={"shrink-0 text-netbird"} aria-hidden={"true"} />
                <div className={"flex min-w-0 flex-1 flex-col leading-tight"}>
                    <span
                        className={
                            "flex min-w-0 items-baseline text-[0.81rem] font-medium text-nb-gray-100"
                        }
                    >
                        <TruncatedText
                            text={transferTitle(transfer)}
                            className={"block min-w-0 truncate"}
                        />
                        <span className={"shrink-0 font-normal text-nb-gray-400"}>
                            {" · "}
                            {formatBytes(transfer.totalSize)}
                        </span>
                    </span>
                    <span className={"truncate text-xs text-nb-gray-400"}>
                        {t("files.offer.subtitle", { peer: transfer.peerName })}
                    </span>
                </div>
            </div>
            <div className={"flex items-center gap-2 pl-[26px]"}>
                <Button
                    variant={"primary"}
                    size={"xs"}
                    disabled={busy}
                    onClick={() => void decide(true)}
                >
                    {t("files.offer.accept")}
                </Button>
                <Button
                    variant={"secondary"}
                    size={"xs"}
                    disabled={busy}
                    onClick={() => void decide(false)}
                >
                    {t("files.offer.decline")}
                </Button>
            </div>
        </div>
    );
};

const TransferRow = ({ transfer, onChanged }: RowProps) => {
    const { t } = useTranslation();
    const [copied, setCopied] = useState(false);
    const isText = isTextTransfer(transfer);
    const live = !isTerminalState(transfer.state);
    const delivered =
        !transfer.outgoing &&
        transfer.state === TransferState.Completed &&
        (transfer.deliveredPaths ?? []).length > 0;
    const progress =
        transfer.state === TransferState.Transferring && transfer.totalSize > 0
            ? Math.min(100, Math.floor((transfer.transferred / transfer.totalSize) * 100))
            : null;

    const peerLabel = transfer.outgoing
        ? t("files.row.to", { peer: transfer.peerName })
        : t("files.row.from", { peer: transfer.peerName });

    let stateLabel: string;
    if (progress !== null) {
        stateLabel = t("files.state.progress", { percent: progress });
    } else if (transfer.state === TransferState.Completed) {
        stateLabel = t(transfer.outgoing ? "files.state.sent" : "files.state.received");
    } else if (
        transfer.state === TransferState.Failed &&
        transfer.reason === FailureReason.Unreachable
    ) {
        stateLabel = t("files.state.unreachable");
    } else {
        stateLabel = t(stateLabelKey(transfer.state));
    }

    const stateClass = outcomeClass(transfer, progress !== null);
    const time = timeLabel(transfer.createdAt as unknown as string);

    const copyText = async () => {
        await navigator.clipboard.writeText(transfer.files[0]?.text ?? "");
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <div
            className={cn(
                "group relative flex items-center gap-2.5 py-2.5 pl-6 pr-4",
                "transition-colors hover:bg-nb-gray-900/40",
                "wails-no-draggable",
            )}
        >
            {transfer.outgoing ? (
                <ArrowUpIcon size={15} className={"shrink-0 text-netbird"} aria-hidden={"true"} />
            ) : (
                <ArrowDownIcon
                    size={15}
                    className={"shrink-0 text-green-400"}
                    aria-hidden={"true"}
                />
            )}
            <div className={"flex min-w-0 flex-1 flex-col gap-0.5 leading-tight"}>
                <TruncatedText
                    text={transferTitle(transfer)}
                    className={cn(
                        "block truncate text-[0.81rem] font-medium text-nb-gray-100",
                        isText && "italic",
                    )}
                />
                <TruncatedText
                    text={peerLabel}
                    className={"block truncate text-xs text-nb-gray-400"}
                />
                <span className={"flex min-w-0 items-baseline text-xs text-nb-gray-500"}>
                    <span className={"shrink-0 tabular-nums"}>{time}</span>
                    {!isText && (
                        <span className={"shrink-0"}>
                            {" · "}
                            {formatBytes(transfer.totalSize)}
                        </span>
                    )}
                </span>
            </div>
            {/* Own column, capped: the window is a fixed 900px and some
                translations of the state labels are long enough to eat the
                file name if they are given free rein. */}
            <span
                className={cn(
                    "max-w-[8.5rem] shrink-0 truncate pl-2 text-xs",
                    stateClass,
                    "transition-opacity group-hover:opacity-0",
                )}
            >
                {stateLabel}
            </span>
            {/* The window is a fixed 900px wide and cannot be resized, so the
                row actions overlay the status column on hover instead of
                reserving width that the file name would otherwise lose. */}
            <div
                className={cn(
                    "absolute right-4 top-1/2 flex -translate-y-1/2 items-center gap-1",
                    // Fades the covered status text out rather than sitting on
                    // a flat block, which would not match the row's hover tint.
                    "bg-gradient-to-l from-nb-gray-940 via-nb-gray-940 to-transparent pl-8",
                    "opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100",
                )}
            >
                {isText && (
                    <RowIconButton label={t("files.action.copy")} onClick={() => void copyText()}>
                        {copied ? (
                            <CheckIcon size={14} className={"text-green-400"} />
                        ) : (
                            <CopyIcon size={14} />
                        )}
                    </RowIconButton>
                )}
                {delivered && (
                    <RowIconButton
                        label={t("files.action.reveal")}
                        onClick={() => void FileDrop.Reveal(transfer.deliveredPaths[0])}
                    >
                        <FolderOpenIcon size={14} />
                    </RowIconButton>
                )}
                {live && (
                    <RowIconButton
                        label={t("files.action.cancel")}
                        onClick={async () => {
                            await FileDrop.Cancel(transfer.id);
                            onChanged();
                        }}
                    >
                        <XIcon size={14} />
                    </RowIconButton>
                )}
                <TransferMenu transfer={transfer} delivered={delivered} onChanged={onChanged} />
            </div>
        </div>
    );
};

const RowIconButton = ({
    label,
    onClick,
    children,
}: {
    label: string;
    onClick: () => void;
    children: React.ReactNode;
}) => (
    <Tooltip content={label}>
        <button
            type={"button"}
            aria-label={label}
            onClick={onClick}
            className={cn(
                "flex h-7 w-7 items-center justify-center rounded-md",
                "text-nb-gray-300 hover:bg-nb-gray-900 hover:text-nb-gray-100",
                "cursor-default outline-none transition-colors",
                "focus-visible:ring-2 focus-visible:ring-white/60",
            )}
        >
            {children}
        </button>
    </Tooltip>
);

const TransferMenu = ({ transfer, delivered, onChanged }: RowProps & { delivered: boolean }) => {
    const { t } = useTranslation();
    const confirm = useConfirm();

    const setRule = async (rule: PeerRule) => {
        await FileDrop.SetPeerRule(transfer.peerKey, rule);
        onChanged();
    };

    const remove = async () => {
        const ok = await confirm({
            title: t("files.delete.title"),
            description: t("files.delete.message"),
            confirmLabel: t("common.delete"),
            danger: true,
        });
        if (!ok) return;
        await FileDrop.Delete(transfer.id);
        onChanged();
    };

    return (
        // modal={false}: the item handler opens a confirm dialog, and a modal
        // dropdown would keep the focus trap that the dialog then fights over.
        <DropdownMenu modal={false}>
            <DropdownMenuTrigger asChild>
                <button
                    type={"button"}
                    aria-label={t("files.action.more")}
                    className={cn(
                        "flex h-7 w-7 items-center justify-center rounded-md",
                        "text-nb-gray-300 hover:bg-nb-gray-900 hover:text-nb-gray-100",
                        "cursor-default outline-none transition-colors",
                        "focus-visible:ring-2 focus-visible:ring-white/60",
                    )}
                >
                    <MoreVerticalIcon size={14} />
                </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align={"end"}>
                {delivered && (
                    <DropdownMenuItem
                        onClick={() => void FileDrop.Open(transfer.deliveredPaths[0])}
                    >
                        <FolderOpenIcon size={14} className={"mr-2"} />
                        {t("files.action.open")}
                    </DropdownMenuItem>
                )}
                {!transfer.outgoing && (
                    <>
                        <DropdownMenuItem onClick={() => void setRule(PeerRule.Always)}>
                            <ShieldCheckIcon size={14} className={"mr-2"} />
                            {t("files.action.alwaysAccept")}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => void setRule(PeerRule.Block)}>
                            <BanIcon size={14} className={"mr-2"} />
                            {t("files.action.block")}
                        </DropdownMenuItem>
                    </>
                )}
                <DropdownMenuItem variant={"danger"} onClick={() => void remove()}>
                    <Trash2Icon size={14} className={"mr-2"} />
                    {t("files.action.delete")}
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
};
