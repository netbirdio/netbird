import { GlobeOffIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "./EmptyState";

export const NotConnectedState = () => {
    const { t } = useTranslation();
    return (
        <div
            className={
                "h-full min-h-[260px] flex-1 flex items-center justify-center px-6 pb-20 top-1 relative"
            }
        >
            <EmptyState
                icon={GlobeOffIcon}
                title={t("notConnected.title")}
                description={t("notConnected.description")}
            />
        </div>
    );
};
