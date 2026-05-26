import { useTranslation } from "react-i18next";
import { SwitchItem } from "@/components/SwitchItem";
import { SwitchItemGroup } from "@/components/SwitchItemGroup";

export type NetworkFilter = "all" | "selected" | "overlapping";

type Props = {
    value: NetworkFilter;
    onChange: (value: NetworkFilter) => void;
    counts: Record<NetworkFilter, number>;
};

export const NetworkFilters = ({ value, onChange, counts }: Props) => {
    const { t, i18n } = useTranslation();
    const filters: { value: NetworkFilter; label: string }[] = [
        { value: "all", label: t("networks.filter.all") },
        { value: "selected", label: t("networks.filter.selected") },
        { value: "overlapping", label: t("networks.filter.overlapping") },
    ];

    return (
        <SwitchItemGroup
            key={i18n.language}
            value={value}
            onChange={(v) => onChange(v as NetworkFilter)}
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
