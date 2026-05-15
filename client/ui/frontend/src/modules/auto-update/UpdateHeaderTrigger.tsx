import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ArrowUpCircleIcon } from "lucide-react";
import { IconButton } from "@/components/IconButton.tsx";
import { Tooltip } from "@/components/Tooltip.tsx";
import { useClientVersion } from "@/modules/auto-update/ClientVersionContext";

export const UpdateHeaderTrigger = () => {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { updateAvailable } = useClientVersion();

    if (!updateAvailable) return null;

    return (
        <Tooltip content={t("update.header.tooltip")}>
            <div className={"relative h-11 w-11 flex items-center justify-center"}>
                <span
                    className={
                        "animate-ping absolute inline-flex h-[15px] w-[15px] rounded-full bg-netbird opacity-20 pointer-events-none"
                    }
                />
                <IconButton
                    icon={ArrowUpCircleIcon}
                    iconClassName={"text-netbird"}
                    onClick={() =>
                        navigate("/settings", { state: { tab: "about" } })
                    }
                    className={"absolute inset-0"}
                />
            </div>
        </Tooltip>
    );
};
