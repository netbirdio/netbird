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

export type NetworkFilter = "all" | "active" | "overlapping";

type Props = {
    value: NetworkFilter;
    onChange: (value: NetworkFilter) => void;
    counts: Record<NetworkFilter, number>;
    disabled?: boolean;
};

export const NetworkFilters = ({ value, onChange, counts, disabled }: Props) => {
    const { t } = useTranslation();
    const [open, setOpen] = useState(false);
    const filters: { value: NetworkFilter; label: string }[] = [
        { value: "all", label: t("networks.filter.all") },
        { value: "active", label: t("networks.filter.active") },
        { value: "overlapping", label: t("networks.filter.overlapping") },
    ];
    const active = filters.find((f) => f.value === value) ?? filters[0];

    const handleSelect = (v: NetworkFilter) => {
        onChange(v);
        setOpen(false);
    };

    return (
        <DropdownMenu open={open} onOpenChange={setOpen}>
            <DropdownMenuTrigger
                disabled={disabled}
                className={cn(
                    "inline-flex items-center gap-1.5 h-9 px-2 rounded-md",
                    "text-sm text-nb-gray-200",
                    "outline-none hover:bg-nb-gray-900 data-[state=open]:bg-nb-gray-900 transition-colors duration-150",
                    "disabled:opacity-50 disabled:pointer-events-none",
                    "wails-no-draggable cursor-default",
                )}
            >
                <ListFilter size={14} className={"shrink-0"} />
                <span>
                    {active.label} <span className={"tabular-nums"}>({counts[active.value]})</span>
                </span>
                <ChevronDown size={14} className={"ml-0.5 shrink-0"} />
            </DropdownMenuTrigger>
            <DropdownMenuContent align={"end"} className={"min-w-[10rem]"}>
                {filters.map((f) => {
                    const checked = f.value === value;
                    return (
                        <DropdownMenuItem
                            key={f.value}
                            onClick={() => handleSelect(f.value)}
                            className={"gap-2"}
                        >
                            <span className={"flex-1 truncate"}>
                                {f.label}{" "}
                                <span className={"tabular-nums"}>({counts[f.value]})</span>
                            </span>
                            <span className={"w-4 shrink-0 flex items-center justify-center"}>
                                {checked && <CheckIcon size={14} className={"text-netbird"} />}
                            </span>
                        </DropdownMenuItem>
                    );
                })}
            </DropdownMenuContent>
        </DropdownMenu>
    );
};
