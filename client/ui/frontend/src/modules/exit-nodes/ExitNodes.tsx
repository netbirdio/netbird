import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { WaypointsIcon } from "lucide-react";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/SearchInput";
import { EmptyState } from "@/components/EmptyState";
import { NoResults } from "@/components/NoResults";
import { useStatus } from "@/modules/daemon-status/StatusContext";
import { useNetworks } from "@/modules/networks/NetworksContext";
import { ExitNodesList } from "./ExitNodesList";

export const ExitNodes = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";
    const { exitNodes, toggleExitNode } = useNetworks();
    const [search, setSearch] = useState("");
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        const matches = exitNodes.filter((r) => {
            if (!q) return true;
            return r.id.toLowerCase().includes(q);
        });
        return matches.sort((a, b) => {
            if (a.selected !== b.selected) return a.selected ? -1 : 1;
            return a.id.localeCompare(b.id);
        });
    }, [exitNodes, search]);

    if (isConnected && exitNodes.length === 0) {
        return (
            <div
                className={
                    "flex-1 flex items-center justify-center px-6 pb-20 w-full h-full min-h-0"
                }
            >
                <EmptyState
                    icon={WaypointsIcon}
                    title={t("exitNodes.empty.title")}
                    description={t("exitNodes.empty.description")}
                    learnMoreUrl={"https://docs.netbird.io/how-to/exit-node"}
                    learnMoreTopic={t("nav.exitNode.title")}
                />
            </div>
        );
    }

    return (
        <div className={"flex flex-col w-full h-full min-h-0"}>
            <div className={"flex items-center gap-2 px-6 py-2.5 border-b border-nb-gray-910"}>
                <div className={"flex-1 min-w-0"}>
                    <SearchInput
                        ref={searchRef}
                        placeholder={t("exitNodes.search.placeholder")}
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
            </div>
            <ScrollArea.Root type={"auto"} className={"flex-1 min-h-0 overflow-hidden"}>
                <ScrollArea.Viewport className={"h-full w-full"}>
                    {filtered.length === 0 ? (
                        <NoResults />
                    ) : (
                        <ExitNodesList data={filtered} onToggle={toggleExitNode} />
                    )}
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
        </div>
    );
};
