import * as RadioGroup from "@radix-ui/react-radio-group";
import { useTranslation } from "react-i18next";
import type { Network } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";

const NONE_VALUE = "__none__";

type Props = {
    data: Network[];
    onToggle: (id: string, selected: boolean) => void;
};

export const ExitNodesList = ({ data, onToggle }: Props) => {
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
