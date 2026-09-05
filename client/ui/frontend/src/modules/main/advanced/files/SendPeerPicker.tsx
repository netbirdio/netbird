import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { ChevronLeftIcon, ClipboardIcon, Search, SendIcon } from "lucide-react";
import { FileDrop } from "@bindings/services";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { shortenDns } from "@/lib/formatters";
import { useStatus } from "@/contexts/StatusContext";
import { ClipboardPreview } from "@/components/ClipboardPreview";
import { dotClass, peerStatusLabelKey } from "@/modules/main/advanced/peers/Peers";

export type SendMode = "files" | "clipboard";

type Props = {
    children: ReactNode;
    onPick: (peer: PeerStatus, mode: SendMode, clipboard: string) => void;
};

const itemClass = cn(
    "my-0.5 flex cursor-default items-center gap-2",
    "rounded-md px-2 py-2 outline-none",
    "text-xs text-nb-gray-200",
    "data-[selected=true]:bg-nb-gray-850 data-[selected=true]:text-nb-gray-50",
);

const noticeClass = "px-3 py-4 text-center text-[0.7rem] text-nb-gray-400";

const modeLabelKey = (mode: SendMode): string =>
    mode === "files" ? "peers.details.sendFile" : "peers.details.sendClipboard";

// What to send first, then to whom: the payload is the cheap, two-option
// decision, so it gets out of the way before the list that needs searching.
export const SendPeerPicker = ({ children, onPick }: Props) => {
    const [open, setOpen] = useState(false);
    const [mode, setMode] = useState<SendMode | null>(null);
    const [clipboard, setClipboard] = useState("");
    const { status } = useStatus();

    // Read on open so the clipboard entry can be disabled and previewed before
    // the peer is chosen, instead of failing after it.
    useEffect(() => {
        if (!open) return;
        let cancelled = false;
        FileDrop.ClipboardText()
            .then((text) => {
                if (!cancelled) setClipboard(text ?? "");
            })
            .catch(() => {
                if (!cancelled) setClipboard("");
            });
        return () => {
            cancelled = true;
        };
    }, [open]);

    // A peer without an overlay address has nothing to dial. Connection state
    // is deliberately not a filter: an idle peer is the normal resting state
    // under lazy connections, and the transfer's own packets wake it.
    const peers = useMemo(
        () =>
            (status?.peers ?? [])
                .filter((p) => p.ip !== "")
                .sort((a, b) =>
                    (a.fqdn || a.ip).toLowerCase().localeCompare((b.fqdn || b.ip).toLowerCase()),
                ),
        [status?.peers],
    );

    const setOpenState = (next: boolean) => {
        setOpen(next);
        if (!next) setMode(null);
    };

    const choose = (peer: PeerStatus) => {
        if (!mode) return;
        const picked = mode;
        const text = clipboard;
        setOpenState(false);
        onPick(peer, picked, text);
    };

    return (
        <Popover.Root open={open} onOpenChange={setOpenState}>
            <Popover.Trigger asChild>{children}</Popover.Trigger>
            <Popover.Portal>
                <Popover.Content
                    align={"end"}
                    sideOffset={6}
                    className={cn(
                        "wails-no-draggable z-50 w-64 select-none rounded-lg p-1 shadow-lg",
                        "border border-nb-gray-850 bg-nb-gray-920",
                        "data-[side=bottom]:origin-top data-[side=top]:origin-bottom",
                        "data-[state=open]:animate-in data-[state=open]:fade-in-0",
                        "data-[state=open]:zoom-in-95",
                        "data-[side=bottom]:slide-in-from-top-1",
                        "data-[side=top]:slide-in-from-bottom-1",
                        "duration-150 ease-out",
                    )}
                >
                    {mode ? (
                        <PeerStep
                            mode={mode}
                            clipboard={clipboard}
                            peers={peers}
                            onBack={() => setMode(null)}
                            onSelect={choose}
                        />
                    ) : (
                        <ModeStep clipboard={clipboard} onChoose={setMode} />
                    )}
                </Popover.Content>
            </Popover.Portal>
        </Popover.Root>
    );
};

const ModeStep = ({
    clipboard,
    onChoose,
}: {
    clipboard: string;
    onChoose: (mode: SendMode) => void;
}) => {
    const { t } = useTranslation();
    const rootRef = useRef<HTMLDivElement>(null);
    const hasClipboard = clipboard !== "";

    // This step has no Command.Input, and cmdk drives arrows/Enter from the
    // focused root, so focus it on mount to keep the flow keyboard-navigable.
    useEffect(() => {
        rootRef.current?.focus();
    }, []);

    return (
        <Command loop ref={rootRef} className={"flex flex-col outline-none"}>
            <Command.List>
                <Command.Item
                    value={"files"}
                    onSelect={() => onChoose("files")}
                    className={itemClass}
                >
                    <SendIcon size={13} aria-hidden={"true"} className={"shrink-0"} />
                    <span className={"min-w-0 flex-1 truncate"}>{t("peers.details.sendFile")}</span>
                </Command.Item>
                <Command.Item
                    value={"clipboard"}
                    disabled={!hasClipboard}
                    onSelect={() => onChoose("clipboard")}
                    className={cn(itemClass, "data-[disabled=true]:opacity-40")}
                >
                    <ClipboardIcon size={13} aria-hidden={"true"} className={"shrink-0"} />
                    <span className={"min-w-0 flex-1 truncate"}>
                        {t("peers.details.sendClipboard")}
                    </span>
                    {!hasClipboard && (
                        <span className={"shrink-0 text-[0.65rem] text-nb-gray-400"}>
                            {t("peers.details.sendClipboard.empty")}
                        </span>
                    )}
                </Command.Item>
            </Command.List>
        </Command>
    );
};

const PeerStep = ({
    mode,
    clipboard,
    peers,
    onBack,
    onSelect,
}: {
    mode: SendMode;
    clipboard: string;
    peers: PeerStatus[];
    onBack: () => void;
    onSelect: (peer: PeerStatus) => void;
}) => {
    const { t } = useTranslation();

    return (
        <Command
            loop
            className={"flex flex-col"}
            onKeyDown={(e) => {
                // Escape steps back to the mode choice rather than discarding
                // the whole flow; a second Escape then closes the popover.
                if (e.key === "Escape") {
                    e.preventDefault();
                    e.stopPropagation();
                    onBack();
                }
            }}
        >
            <button
                type={"button"}
                onClick={onBack}
                aria-label={t("files.send.back")}
                className={cn(
                    "flex w-full items-center gap-1.5 rounded-md px-2 py-1.5",
                    "cursor-default text-left outline-none transition-colors",
                    "text-nb-gray-400 hover:text-nb-gray-100",
                    "focus-visible:ring-2 focus-visible:ring-white/60",
                )}
            >
                <ChevronLeftIcon size={12} aria-hidden={"true"} className={"shrink-0"} />
                <span className={"min-w-0 flex-1 truncate text-xs font-medium text-nb-gray-200"}>
                    {t(modeLabelKey(mode))}
                </span>
            </button>
            {mode === "clipboard" && <ClipboardPreview text={clipboard} className={"mx-1 mb-1"} />}
            <div className={"-mx-1 my-1 h-px bg-nb-gray-850"} />
            <div role={"search"} className={"flex h-8 items-center gap-2 px-2 pb-1"}>
                <Search size={14} aria-hidden={"true"} className={"shrink-0 text-nb-gray-200"} />
                <Command.Input
                    autoFocus
                    placeholder={t("files.send.search")}
                    aria-label={t("files.send.search")}
                    className={cn(
                        "w-full border-none bg-transparent text-xs outline-none",
                        "text-nb-gray-100 placeholder:text-nb-gray-300",
                    )}
                />
            </div>
            <ScrollArea.Root type={"auto"} className={"-mx-1 overflow-hidden"}>
                <ScrollArea.Viewport className={"max-h-64 px-1"}>
                    <Command.List>
                        <Command.Empty>
                            <div className={noticeClass}>{t("files.send.empty")}</div>
                        </Command.Empty>
                        {peers.length === 0 && (
                            <div className={noticeClass}>{t("files.send.noPeers")}</div>
                        )}
                        {peers.map((peer) => (
                            <Command.Item
                                key={peer.pubKey}
                                value={`${peer.fqdn} ${peer.ip}`}
                                onSelect={() => onSelect(peer)}
                                className={itemClass}
                            >
                                <span
                                    role={"img"}
                                    aria-label={t(peerStatusLabelKey(peer.connStatus))}
                                    className={cn(
                                        "h-1.5 w-1.5 shrink-0 rounded-full",
                                        dotClass(peer.connStatus),
                                    )}
                                />
                                <span className={"min-w-0 flex-1 truncate font-medium"}>
                                    {shortenDns(peer.fqdn) || peer.ip}
                                </span>
                            </Command.Item>
                        ))}
                    </Command.List>
                </ScrollArea.Viewport>
                <ScrollArea.Scrollbar
                    orientation={"vertical"}
                    className={"flex w-1.5 touch-none select-none bg-transparent"}
                >
                    <ScrollArea.Thumb
                        className={cn(
                            "relative flex-1 rounded-full",
                            "bg-nb-gray-800 hover:bg-nb-gray-700",
                        )}
                    />
                </ScrollArea.Scrollbar>
            </ScrollArea.Root>
        </Command>
    );
};
