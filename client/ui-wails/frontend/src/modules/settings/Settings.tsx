import { useState } from "react";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { SettingsNavigationTriggers } from "@/modules/settings/SettingsNavigationTriggers.tsx";
import { SettingsProvider } from "@/modules/settings/SettingsContext.tsx";
import { SettingsGeneral } from "@/modules/settings/SettingsGeneral.tsx";
import { SettingsNetwork } from "@/modules/settings/SettingsNetwork.tsx";
import { SettingsSecurity } from "@/modules/settings/SettingsSecurity.tsx";
import { SettingsSSH } from "@/modules/settings/SettingsSSH.tsx";
import { SettingsAdvanced } from "@/modules/settings/SettingsAdvanced.tsx";
import { SettingsTroubleshooting } from "@/modules/settings/SettingsTroubleshooting.tsx";
import { SettingsAbout } from "@/modules/settings/SettingsAbout.tsx";

export const Settings = () => {
    const [active, setActive] = useState("general");

    return (
        <VerticalTabs
            value={active}
            onValueChange={setActive}
            className={"wails-draggable p-4"}
        >
            <SettingsNavigationTriggers />
            <MainRightSide>
                <SettingsProvider>
                    <VerticalTabs.Content value={"general"}>
                        <SettingsGeneral />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"network"}>
                        <SettingsNetwork />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"security"}>
                        <SettingsSecurity />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"ssh"}>
                        <SettingsSSH />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"advanced"}>
                        <SettingsAdvanced />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"troubleshooting"}>
                        <SettingsTroubleshooting />
                    </VerticalTabs.Content>
                    <VerticalTabs.Content value={"about"}>
                        <SettingsAbout />
                    </VerticalTabs.Content>
                </SettingsProvider>
            </MainRightSide>
        </VerticalTabs>
    );
};
