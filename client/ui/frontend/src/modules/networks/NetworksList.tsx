import { useTranslation } from "react-i18next";
import type { Network } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";

const dotClass = (selected: boolean): string =>
    selected ? "bg-green-400" : "bg-nb-gray-500";

type Props = {
    data: Network[];
    onToggle: (id: string, selected: boolean) => void;
};

export const NetworksList = ({ data, onToggle }: Props) => {
    const { t } = useTranslation();
    if (data.length === 0) {
        return (
            <div className={"py-12 text-center text-sm text-nb-gray-400"}>
                {t("networks.empty")}
            </div>
        );
    }

    return (
        <ul className={"flex flex-col"}>
            {data.map((n) => (
                <li
                    key={n.id}
                    className={"flex items-center gap-3 px-7 py-3 min-w-0"}
                >
                    <button
                        type={"button"}
                        onClick={() => onToggle(n.id, n.selected)}
                        className={cn(
                            "h-2 w-2 rounded-full shrink-0 cursor-pointer",
                            dotClass(n.selected),
                        )}
                        title={n.selected ? t("networks.selected") : t("networks.unselected")}
                    />
                    <CopyToClipboard message={n.id} className={"min-w-0 flex-1"}>
                        <span className={"text-[0.81rem] font-medium text-nb-gray-100"}>
                            {n.id}
                        </span>
                    </CopyToClipboard>
                    <CopyToClipboard
                        message={n.range}
                        className={cn("ml-auto shrink-0", "relative left-2.5")}
                    >
                        <span className={"text-xs font-mono text-nb-gray-400"}>
                            {n.range}
                        </span>
                    </CopyToClipboard>
                </li>
            ))}
        </ul>
    );
};
