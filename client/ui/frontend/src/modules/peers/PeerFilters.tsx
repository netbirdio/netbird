import { SwitchItem } from "@/components/SwitchItem";
import { SwitchItemGroup } from "@/components/SwitchItemGroup";

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
        <SwitchItemGroup
            value={value}
            onChange={(v) => onChange(v as StatusFilter)}
            className={"w-full"}
        >
            {FILTERS.map((f) => (
                <SwitchItem key={f.value} value={f.value} className={"flex-1"}>
                    {f.label}
                    <span className={"font-normal text-nb-gray-200"}>
                        {counts[f.value]}
                    </span>
                </SwitchItem>
            ))}
        </SwitchItemGroup>
    );
};
