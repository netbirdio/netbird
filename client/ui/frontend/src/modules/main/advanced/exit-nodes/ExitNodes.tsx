import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as RadioGroup from "@radix-ui/react-radio-group";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { WaypointsIcon } from "lucide-react";
import type { Network } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { SearchInput } from "@/components/inputs/SearchInput";
import { EmptyState } from "@/components/empty-state/EmptyState";
import { NoResults } from "@/components/empty-state/NoResults";
import { useStatus } from "@/contexts/StatusContext";
import { useNetworks } from "@/contexts/NetworksContext";
import { mockExitNodes, mockOr } from "@/lib/mock";

const NONE_VALUE = "__none__";

export const ExitNodes = () => {
    const { t } = useTranslation();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";
    const { exitNodes: realExitNodes, toggleExitNode } = useNetworks();
    const exitNodes = mockOr(realExitNodes, mockExitNodes);
    const [search, setSearch] = useState("");
    const searchRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        searchRef.current?.focus();
    }, []);

    // Initial order: active-first, then by id. After that, positions are sticky
    // — toggling a row doesn't move it. Mirrors the networks-list behavior so
    // the optimistic radio flip paints in place instead of the row jumping to
    // the top.
    const orderRef = useRef<string[]>([]);
    const ordered = useMemo(() => {
        const byId = new Map(exitNodes.map((n) => [n.id, n]));
        const kept = orderRef.current.filter((id) => byId.has(id));
        const known = new Set(kept);
        const fresh = exitNodes
            .filter((n) => !known.has(n.id))
            .sort((a, b) => {
                if (a.selected !== b.selected) return a.selected ? -1 : 1;
                return a.id.localeCompare(b.id);
            })
            .map((n) => n.id);
        const next = [...kept, ...fresh];
        orderRef.current = next;
        return next.map((id) => byId.get(id)!);
    }, [exitNodes]);

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();
        if (!q) return ordered;
        return ordered.filter((r) => r.id.toLowerCase().includes(q));
    }, [ordered, search]);

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

type ExitNodesListProps = {
    data: Network[];
    onToggle: (id: string, selected: boolean) => void;
};

const ExitNodesList = ({ data, onToggle }: ExitNodesListProps) => {
    const { t } = useTranslation();
    const active = data.find((n) => n.selected) ?? null;
    const value = active?.id ?? NONE_VALUE;

    const handleChange = (next: string) => {
        if (next === value) return;
        if (next === NONE_VALUE) {
            if (active) onToggle(active.id, true);
            return;
        }
        onToggle(next, false);
    };

    return (
        <RadioGroup.Root
            value={value}
            onValueChange={handleChange}
            className={"flex flex-col"}
        >
            <Row value={NONE_VALUE} label={t("exitNodes.none")} first />
            {data.map((n) => (
                <Row key={n.id} value={n.id} label={n.id} />
            ))}
        </RadioGroup.Root>
    );
};

type RowProps = {
    value: string;
    label: string;
    first?: boolean;
};

const Row = ({ value, label, first }: RowProps) => (
    <RadioGroup.Item
        value={value}
        className={cn(
            "group flex items-center gap-2.5 pl-6 pr-8 py-3 min-w-0 w-full",
            first && "mt-2",
            "hover:bg-nb-gray-900/40 transition-colors",
            "wails-no-draggable cursor-pointer outline-none text-left",
        )}
    >
        <span
            className={
                "min-w-0 flex-1 text-[0.81rem] font-medium text-nb-gray-100 truncate"
            }
        >
            {label}
        </span>
        <span
            className={cn(
                "h-4 w-4 shrink-0 rounded-full border",
                "border-nb-gray-700 bg-nb-gray-900",
                "flex items-center justify-center",
                "group-data-[state=checked]:border-netbird group-data-[state=checked]:bg-netbird",
            )}
        >
            <RadioGroup.Indicator
                className={"h-2 w-2 rounded-full bg-white"}
            />
        </span>
    </RadioGroup.Item>
);
