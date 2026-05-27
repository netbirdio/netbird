import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { AnimatePresence, motion, type Transition } from "framer-motion";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { ArrowLeftIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { useStatus } from "@/modules/daemon-status/StatusContext";
import { PeerDetails } from "./PeerDetails";
import { usePeerDetail } from "./PeerDetailContext";

const DEFAULT_TRANSITION: Transition = {
    duration: 0.32,
    ease: [0.32, 0.72, 0, 1],
};

const dotClass = (connStatus: string): string => {
    switch (connStatus) {
        case "Connected":
            return "bg-green-400";
        case "Connecting":
            return "bg-yellow-300 animate-pulse-slow";
        default:
            return "bg-nb-gray-500";
    }
};

type Props = {
    transition?: Transition;
};

export const PeerDetailPanel = ({ transition = DEFAULT_TRANSITION }: Props) => {
    const { t } = useTranslation();
    const { selected, setSelected } = usePeerDetail();
    const { status } = useStatus();

    // Keep `selected` in sync with the live peer list so the panel reflects
    // status / latency / byte updates without re-opening. If the peer
    // disappears, close the panel.
    useEffect(() => {
        if (!selected) return;
        const peers = status?.peers ?? [];
        const fresh = peers.find((p) => p.pubKey === selected.pubKey);
        if (!fresh) {
            setSelected(null);
            return;
        }
        if (fresh !== selected) setSelected(fresh);
    }, [status, selected, setSelected]);

    // Esc closes the panel.
    useEffect(() => {
        if (!selected) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") setSelected(null);
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [selected, setSelected]);

    return (
        <AnimatePresence>
            {selected && (
                <motion.div
                    initial={{ x: "100%" }}
                    animate={{ x: 0 }}
                    exit={{ x: "100%" }}
                    transition={transition}
                    className={cn("absolute inset-0 z-20 flex flex-col", "bg-nb-gray-940")}
                >
                    <div
                        className={cn(
                            "shrink-0 flex items-center gap-3",
                            "px-3 h-12 border-b border-nb-gray-910",
                        )}
                    >
                        <button
                            type={"button"}
                            onClick={() => setSelected(null)}
                            aria-label={t("common.close")}
                            className={cn(
                                "shrink-0 h-8 w-8 rounded-md flex items-center justify-center",
                                "text-nb-gray-300 hover:bg-nb-gray-910 hover:text-nb-gray-100",
                                "transition-colors outline-none cursor-default",
                                "wails-no-draggable",
                            )}
                        >
                            <ArrowLeftIcon size={16} />
                        </button>
                        <span
                            className={cn(
                                "h-2 w-2 rounded-full shrink-0",
                                dotClass(selected.connStatus),
                            )}
                            title={selected.connStatus}
                        />
                        <span className={"min-w-0 text-sm font-medium text-nb-gray-100 truncate"}>
                            {selected.fqdn || selected.ip}
                        </span>
                    </div>
                    <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                        <ScrollArea.Viewport className={"h-full w-full"}>
                            <PeerDetails peer={selected} />
                        </ScrollArea.Viewport>
                        <ScrollArea.Scrollbar
                            orientation={"vertical"}
                            className={cn(
                                "flex select-none touch-none transition-colors",
                                "w-1.5 bg-transparent py-1",
                            )}
                        >
                            <ScrollArea.Thumb
                                className={
                                    "flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative"
                                }
                            />
                        </ScrollArea.Scrollbar>
                    </ScrollArea.Root>
                </motion.div>
            )}
        </AnimatePresence>
    );
};
