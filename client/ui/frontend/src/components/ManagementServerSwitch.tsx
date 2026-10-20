import { useTranslation } from "react-i18next";
import netbirdLogo from "@/assets/logos/netbird.svg";
import { SwitchItem } from "@/components/switches/SwitchItem";
import { SwitchItemGroup } from "@/components/switches/SwitchItemGroup";
import { ManagementMode } from "@/hooks/useManagementUrl.ts";

type Props = {
    value: ManagementMode;
    onChange: (mode: ManagementMode) => void;
    fullWidth?: boolean;
};

export const ManagementServerSwitch = ({ value, onChange, fullWidth = false }: Props) => {
    const { t, i18n } = useTranslation();
    const itemClass = fullWidth ? "flex-1" : undefined;
    return (
        <SwitchItemGroup
            key={i18n.language}
            value={value}
            onChange={(v) => onChange(v as ManagementMode)}
            aria-label={t("settings.general.management.label")}
            className={fullWidth ? "w-full" : undefined}
        >
            <SwitchItem value={ManagementMode.Cloud} className={itemClass}>
                <img
                    src={netbirdLogo}
                    alt={""}
                    aria-hidden={"true"}
                    className={"aspect-[31/23] h-[0.8rem] shrink-0"}
                />
                {t("settings.general.management.cloud")}
            </SwitchItem>
            <SwitchItem value={ManagementMode.SelfHosted} className={itemClass}>
                {t("settings.general.management.selfHosted")}
            </SwitchItem>
        </SwitchItemGroup>
    );
};
