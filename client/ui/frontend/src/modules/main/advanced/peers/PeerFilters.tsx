import { useState } from "react";
import { CheckIcon, ChevronDown, ListFilter } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";

export type StatusFilter = "all" | "online" | "offline";

type Props = {
    value: StatusFilter;
    onChange: (value: StatusFilter) => void;
    counts: Record<StatusFilter, number>;
    disabled?: boolean;
};

export const PeerFilters = ({ value, onChange, counts, disabled }: Props) => {
    const { t } = useTranslation();
    const [open, setOpen] = useState(false);
    const filters: { value: StatusFilter; label: string }[] = [
        { value: "all", label: t("peers.filter.all") },
        { value: "online", label: t("peers.filter.online") },
        { value: "offline", label: t("peers.filter.offline") },
    ];
    const active = filters.find((f) => f.value === value) ?? filters[0];

    const handleSelect = (v: StatusFilter) => {
        onChange(v);
        setOpen(false);
    };

    return (
        <DropdownMenu open={open} onOpenChange={setOpen}>
            <DropdownMenuTrigger
                disabled={disabled}
                tabIndex={0}
                aria-label={t("common.filter")}
                className={cn(
                    "inline-flex h-9 items-center gap-1.5 rounded-md px-2",
                    "text-sm text-nb-gray-200",
                    "outline-none transition-colors duration-150 hover:bg-nb-gray-900 data-[state=open]:bg-nb-gray-900",
                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    "disabled:pointer-events-none disabled:opacity-50",
                    "wails-no-draggable cursor-default",
                )}
            >
                <ListFilter size={14} aria-hidden={"true"} className={"shrink-0"} />
                <span>
                    {active.label} <span className={"tabular-nums"}>({counts[active.value]})</span>
                </span>
                <ChevronDown size={14} aria-hidden={"true"} className={"ml-0.5 shrink-0"} />
            </DropdownMenuTrigger>
            <DropdownMenuContent align={"end"} className={"min-w-[10rem]"}>
                {filters.map((f) => {
                    const checked = f.value === value;
                    return (
                        <DropdownMenuItem
                            key={f.value}
                            onClick={() => handleSelect(f.value)}
                            role={"menuitemradio"}
                            aria-checked={checked}
                            className={"gap-2"}
                        >
                            <span className={"flex-1 truncate"}>
                                {f.label}{" "}
                                <span className={"tabular-nums"}>({counts[f.value]})</span>
                            </span>
                            <span
                                aria-hidden={"true"}
                                className={"flex w-4 shrink-0 items-center justify-center"}
                            >
                                {checked && <CheckIcon size={14} className={"text-netbird"} />}
                            </span>
                        </DropdownMenuItem>
                    );
                })}
            </DropdownMenuContent>
        </DropdownMenu>
    );
};
