import { cn } from "@/lib/cn";

export type StatusFilter = "all" | "online" | "offline";

const FILTERS: { value: StatusFilter; label: string }[] = [
    { value: "all", label: "All" },
    { value: "online", label: "Online" },
    { value: "offline", label: "Offline" },
];

type Props = {
    value: StatusFilter;
    onChange: (value: StatusFilter) => void;
    counts: Record<StatusFilter, number>;
};

export const PeerFilters = ({ value, onChange, counts }: Props) => {
    return (
        <div
            className={
                "flex w-full rounded-md border border-nb-gray-900 bg-nb-gray-940 p-0.5"
            }
        >
            {FILTERS.map((f) => {
                const active = value === f.value;
                return (
                    <button
                        key={f.value}
                        type={"button"}
                        onClick={() => onChange(f.value)}
                        className={cn(
                            "flex-1 inline-flex items-center justify-center gap-1.5 rounded px-2.5 py-2 text-xs font-medium",
                            "transition-colors duration-150 cursor-default outline-none",
                            active
                                ? "bg-nb-gray-800 text-nb-gray-100"
                                : "text-nb-gray-400 hover:text-nb-gray-200",
                        )}
                    >
                        {f.label}
                        <span
                            className={cn(
                                "text-[0.65rem] font-mono",
                                active ? "text-nb-gray-300" : "text-nb-gray-500",
                            )}
                        >
                            {counts[f.value]}
                        </span>
                    </button>
                );
            })}
        </div>
    );
};
