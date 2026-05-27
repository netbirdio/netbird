import { useTranslation } from "react-i18next";
import { SwitchItem } from "@/components/SwitchItem";
import { SwitchItemGroup } from "@/components/SwitchItemGroup";

export type StatusFilter = "all" | "online" | "offline";

type Props = {
    value: StatusFilter;
    onChange: (value: StatusFilter) => void;
    counts: Record<StatusFilter, number>;
    disabled?: boolean;
};

export const PeerFilters = ({ value, onChange, counts, disabled }: Props) => {
    const { t, i18n } = useTranslation();
    const filters: { value: StatusFilter; label: string }[] = [
        { value: "all", label: t("peers.filter.all") },
        { value: "online", label: t("peers.filter.online") },
        { value: "offline", label: t("peers.filter.offline") },
    ];

    return (
        <SwitchItemGroup
            key={i18n.language}
            value={value}
            onChange={(v) => onChange(v as StatusFilter)}
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
