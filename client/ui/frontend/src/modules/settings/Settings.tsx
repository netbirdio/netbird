import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
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
import { SettingsDevelopment } from "@/modules/settings/SettingsDevelopment.tsx";

// The settings window always opens at General. The only way to land on a
// different tab is via navigation state (e.g. the update-available header
// trigger jumps to About). No persistence across opens — a user who wants
// to revisit a deep tab gets there in two clicks.
export const Settings = () => {
    const location = useLocation();
    const navState = location.state as { tab?: string } | null;
    const [active, setActive] = useState(() => navState?.tab ?? "general");

    useEffect(() => {
        if (navState?.tab) setActive(navState.tab);
    }, [navState?.tab, location.key]);

    return (
        <VerticalTabs value={active} onValueChange={setActive} className={"p-4"}>
            <SettingsNavigationTriggers />
            <MainRightSide>
                <ScrollArea.Root
                    type={"auto"}
                    className={"flex-1 min-h-0 overflow-hidden"}
                >
                    <ScrollArea.Viewport className={"h-full w-full"}>
                        <div className={"py-8 px-7"}>
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
                                {import.meta.env.DEV && (
                                    <VerticalTabs.Content value={"development"}>
                                        <SettingsDevelopment />
                                    </VerticalTabs.Content>
                                )}
                            </SettingsProvider>
                        </div>
                    </ScrollArea.Viewport>
                    <ScrollArea.Scrollbar
                        orientation={"vertical"}
                        className={cn(
                            "flex select-none touch-none transition-colors",
                            "w-1.5 bg-transparent py-1",
                        )}
                    >
                        <ScrollArea.Thumb
                            className={
                                "flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative"
                            }
                        />
                    </ScrollArea.Scrollbar>
                </ScrollArea.Root>
            </MainRightSide>
        </VerticalTabs>
    );
};
