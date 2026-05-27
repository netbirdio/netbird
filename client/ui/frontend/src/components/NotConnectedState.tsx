import { UnplugIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "./EmptyState";

export const NotConnectedState = () => {
    const { t } = useTranslation();
    return (
        <div
            className={
                "h-full min-h-[260px] flex items-center justify-center px-6"
            }
        >
            <EmptyState
                icon={UnplugIcon}
                title={t("notConnected.title")}
                description={t("notConnected.description")}
            />
        </div>
    );
};
