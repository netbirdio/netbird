import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
import { isMacOS } from "@/lib/platform";
import { AppRightPanel } from "@/layouts/AppRightPanel.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { SettingsNavigation } from "@/modules/settings/SettingsNavigation.tsx";
import { AutostartSettingsProvider, SettingsProvider } from "@/contexts/SettingsContext.tsx";
import { SettingsGeneral } from "@/modules/settings/SettingsGeneral.tsx";
import { SettingsNetwork } from "@/modules/settings/SettingsNetwork.tsx";
import { SettingsSecurity } from "@/modules/settings/SettingsSecurity.tsx";
import { ProfilesTab } from "@/modules/profiles/ProfilesTab.tsx";
import { SettingsSSH } from "@/modules/settings/SettingsSSH.tsx";
import { SettingsVNC } from "@/modules/settings/SettingsVNC.tsx";
import { SettingsAdvanced } from "@/modules/settings/SettingsAdvanced.tsx";
import { SettingsTroubleshooting } from "@/modules/settings/SettingsTroubleshooting.tsx";
import { SettingsAbout } from "@/modules/settings/SettingsAbout.tsx";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

const EVENT_SETTINGS_OPEN = "netbird:settings:open";

const enum Tab {
    General = "general",
    Network = "network",
    Security = "security",
    Profiles = "profiles",
    SSH = "ssh",
    VNC = "vnc",
    Advanced = "advanced",
    Troubleshooting = "troubleshooting",
    About = "about",
}

const TAB_CONTENT: Record<Tab, ReactNode> = {
    [Tab.General]: <SettingsGeneral />,
    [Tab.Network]: <SettingsNetwork />,
    [Tab.Security]: <SettingsSecurity />,
    [Tab.Profiles]: <ProfilesTab />,
    [Tab.SSH]: <SettingsSSH />,
    [Tab.VNC]: <SettingsVNC />,
    [Tab.Advanced]: <SettingsAdvanced />,
    [Tab.Troubleshooting]: <SettingsTroubleshooting />,
    [Tab.About]: <SettingsAbout />,
};

export const SettingsPage = () => {
    const location = useLocation();
    const navState = location.state as { tab?: string } | null;
    const { mdm, features } = useRestrictions();

    const visibleTabs = useMemo<Tab[]>(() => {
        const editable = !features.disableUpdateSettings;
        const visibility: Record<Tab, boolean> = {
            [Tab.General]: true,
            [Tab.Network]: editable,
            [Tab.Security]: editable,
            [Tab.Profiles]: !features.disableProfiles,
            [Tab.SSH]: mdm.allowServerSSH ?? editable,
            [Tab.VNC]: editable,
            [Tab.Advanced]: editable,
            [Tab.Troubleshooting]: true,
            [Tab.About]: true,
        };
        return (Object.keys(visibility) as Tab[]).filter((t) => visibility[t]);
    }, [features.disableUpdateSettings, features.disableProfiles, mdm.allowServerSSH]);

    const defaultTab = visibleTabs[0];
    const [active, setActive] = useState<string>(() => navState?.tab ?? defaultTab);

    useEffect(() => {
        if (navState?.tab) setActive(navState.tab);
    }, [navState?.tab, location.key]);

    useEffect(() => {
        return Events.On(EVENT_SETTINGS_OPEN, (e: { data: string }) => {
            setActive(e.data || defaultTab);
        });
    }, [defaultTab]);

    // Reset active tab if it got disabled by any feature flag or mdm restrictions
    useEffect(() => {
        if (!visibleTabs.includes(active as Tab)) setActive(defaultTab);
    }, [visibleTabs, active, defaultTab]);

    return (
        <>
            {isMacOS() ? (
                <div className={"wails-draggable h-12 shrink-0 cursor-default select-none"} />
            ) : (
                <div className={"h-px shrink-0 bg-nb-gray-920/0"} />
            )}
            <main className={"flex min-h-0 flex-1"}>
                <VerticalTabs value={active} onValueChange={setActive}>
                    <SettingsNavigation />
                    <AppRightPanel>
                        <AutostartSettingsProvider>
                            <SettingsProvider>
                                <ScrollArea.Root
                                    key={active}
                                    type={"auto"}
                                    className={"min-h-0 flex-1 overflow-hidden"}
                                >
                                    <ScrollArea.Viewport className={"h-full w-full"}>
                                        <div className={"px-7 py-6"}>
                                            {visibleTabs.map((tab) => (
                                                <VerticalTabs.Content key={tab} value={tab}>
                                                    {TAB_CONTENT[tab]}
                                                </VerticalTabs.Content>
                                            ))}
                                        </div>
                                    </ScrollArea.Viewport>
                                    <ScrollArea.Scrollbar
                                        orientation={"vertical"}
                                        className={cn(
                                            "flex touch-none select-none transition-colors",
                                            "w-1.5 bg-transparent py-1",
                                        )}
                                    >
                                        <ScrollArea.Thumb
                                            className={
                                                "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                                            }
                                        />
                                    </ScrollArea.Scrollbar>
                                </ScrollArea.Root>
                            </SettingsProvider>
                        </AutostartSettingsProvider>
                    </AppRightPanel>
                </VerticalTabs>
            </main>
        </>
    );
};
