import { GlobeOffIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "./EmptyState";

export const NotConnectedState = () => {
    const { t } = useTranslation();
    return (
        <div
            className={
                "h-full flex-1 flex items-start justify-center pt-36 top-[0.6rem] px-6 relative"
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
