import { ComponentType } from "react";
import { FunnelXIcon, LucideProps } from "lucide-react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "./EmptyState";

type Props = {
    icon?: ComponentType<LucideProps>;
    title?: string;
    description?: string;
};

export const NoResults = ({ icon = FunnelXIcon, title, description }: Props) => {
    const { t } = useTranslation();
    return (
        <EmptyState
            icon={icon}
            title={title ?? t("common.noResults.title")}
            description={description ?? t("common.noResults.description")}
            className={"relative -top-3.5"}
        />
    );
};
