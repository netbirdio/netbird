import { useTranslation } from "react-i18next";
import { SwitchItem } from "@/components/SwitchItem";
import { SwitchItemGroup } from "@/components/SwitchItemGroup";

export type NetworkFilter = "all" | "active" | "overlapping";

type Props = {
    value: NetworkFilter;
    onChange: (value: NetworkFilter) => void;
    counts: Record<NetworkFilter, number>;
    disabled?: boolean;
};

export const NetworkFilters = ({ value, onChange, counts, disabled }: Props) => {
    const { t, i18n } = useTranslation();
    const filters: { value: NetworkFilter; label: string }[] = [
        { value: "all", label: t("networks.filter.all") },
        { value: "active", label: t("networks.filter.active") },
        { value: "overlapping", label: t("networks.filter.overlapping") },
    ];

    return (
        <SwitchItemGroup
            key={i18n.language}
            value={value}
            onChange={(v) => onChange(v as NetworkFilter)}
            disabled={disabled}
            className={"w-full"}
        >
            {filters.map((f) => (
                <SwitchItem key={f.value} value={f.value} className={"flex-1"}>
                    {f.label}
                    <span className={"tabular-nums"}>({counts[f.value]})</span>
                </SwitchItem>
            ))}
        </SwitchItemGroup>
    );
};
