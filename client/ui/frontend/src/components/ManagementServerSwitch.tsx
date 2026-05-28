import { useTranslation } from "react-i18next";
import netbirdLogo from "@/assets/logos/netbird.svg";
import { SwitchItem } from "@/components/switches/SwitchItem";
import { SwitchItemGroup } from "@/components/switches/SwitchItemGroup";
import { ManagementMode } from "@/hooks/useManagementUrl.ts";

type Props = {
    value: ManagementMode;
    onChange: (mode: ManagementMode) => void;
};

export const ManagementServerSwitch = ({ value, onChange }: Props) => {
    const { t, i18n } = useTranslation();
    return (
        <SwitchItemGroup
            key={i18n.language}
            value={value}
            onChange={(v) => onChange(v as ManagementMode)}
        >
            <SwitchItem value={ManagementMode.Cloud}>
                <img src={netbirdLogo} alt={""} className={"h-[0.8rem] aspect-[31/23] shrink-0"} />
                {t("settings.general.management.cloud")}
            </SwitchItem>
            <SwitchItem value={ManagementMode.SelfHosted}>
                {t("settings.general.management.selfHosted")}
            </SwitchItem>
        </SwitchItemGroup>
    );
};
