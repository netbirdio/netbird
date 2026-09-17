import { GlobeOffIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "./EmptyState";

export const NotConnectedState = () => {
    const { t } = useTranslation();
    return (
        <div className={"relative top-[3rem] w-full"}>
            <EmptyState
                icon={GlobeOffIcon}
                title={t("notConnected.title")}
                description={t("notConnected.description")}
            />
        </div>
    );
};
