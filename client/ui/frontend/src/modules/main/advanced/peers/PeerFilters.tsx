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
    const { t, i18n } = useTranslation();
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
        <DropdownMenu key={i18n.language} open={open} onOpenChange={setOpen}>
            <DropdownMenuTrigger
                disabled={disabled}
                className={cn(
                    "inline-flex items-center gap-1.5 h-9 px-2 rounded-md",
                    "text-sm text-nb-gray-100",
                    "outline-none hover:bg-nb-gray-900 data-[state=open]:bg-nb-gray-900 transition-colors duration-150",
                    "disabled:opacity-50 disabled:pointer-events-none",
                    "wails-no-draggable",
                )}
            >
                <ListFilter size={14} className={"shrink-0"} />
                <span>
                    {active.label}{" "}
                    <span className={"tabular-nums"}>
                        ({counts[active.value]})
                    </span>
                </span>
                <ChevronDown
                    size={14}
                    className={"text-nb-gray-400 ml-0.5 shrink-0"}
                />
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
                                <span className={"tabular-nums"}>
                                    ({counts[f.value]})
                                </span>
                            </span>
                            <span
                                className={
                                    "w-4 shrink-0 flex items-center justify-center"
                                }
                            >
                                {checked && (
                                    <CheckIcon
                                        size={14}
                                        className={"text-netbird"}
                                    />
                                )}
                            </span>
                        </DropdownMenuItem>
                    );
                })}
            </DropdownMenuContent>
        </DropdownMenu>
    );
};
