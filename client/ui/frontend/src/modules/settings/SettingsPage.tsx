import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { cn } from "@/lib/cn";
import { isMacOS } from "@/lib/platform";
import { AppRightPanel } from "@/layouts/AppRightPanel.tsx";
import { VerticalTabs } from "@/components/VerticalTabs.tsx";
import { SettingsNavigation } from "@/modules/settings/SettingsNavigation.tsx";
import {
    AutostartSettingsProvider,
    SettingsProvider,
} from "@/contexts/SettingsContext.tsx";
import { SettingsGeneral } from "@/modules/settings/SettingsGeneral.tsx";
import { SettingsNetwork } from "@/modules/settings/SettingsNetwork.tsx";
import { SettingsSecurity } from "@/modules/settings/SettingsSecurity.tsx";
import { ProfilesTab } from "@/modules/profiles/ProfilesTab.tsx";
import { SettingsSSH } from "@/modules/settings/SettingsSSH.tsx";
import { SettingsAdvanced } from "@/modules/settings/SettingsAdvanced.tsx";
import { SettingsTroubleshooting } from "@/modules/settings/SettingsTroubleshooting.tsx";
import { SettingsAbout } from "@/modules/settings/SettingsAbout.tsx";

const EVENT_SETTINGS_OPEN = "netbird:settings:open";

// The settings window mounts once at app startup (hidden) and stays at the
// single URL `/#/settings` forever — no SetURL between opens, so the
// `AppLayout` provider stack never re-mounts and we never see the
// `SettingsSkeleton` flash mid-reload. Tab is local state, driven by:
//   - the `netbird:settings:open` Wails event from `WindowManager.OpenSettings`
//     (sets the target tab, then Go calls `Show`/`Focus`); and
//   - the same event with payload `"general"` from the close hook, so the
//     window is already on General the next time Show fires (common case).
// In-window navigation state (e.g. the update-available header jump to About)
// still wins for that one render.
//
// The `h-12` draggable strip at the top accounts for the macOS
// `MacTitleBarHiddenInset` setting in services/windowmanager.go (traffic-light
// buttons float over invisible title bar) and mirrors the main window's
// Header height so AppRightPanel ends up the same height in both windows.
export const SettingsPage = () => {
    const location = useLocation();
    const navState = location.state as { tab?: string } | null;
    const [active, setActive] = useState(() => navState?.tab ?? "general");

    useEffect(() => {
        if (navState?.tab) setActive(navState.tab);
    }, [navState?.tab, location.key]);

    useEffect(() => {
        return Events.On(EVENT_SETTINGS_OPEN, (e: { data: string }) => {
            setActive(e.data || "general");
        });
    }, []);

    return (
        <>
            {isMacOS() ? (
                <div
                    className={
                        "wails-draggable cursor-default select-none h-12 shrink-0"
                    }
                />
            ) : (
                <div className={"h-px shrink-0 bg-nb-gray-920/0"} />
            )}
            <VerticalTabs
                value={active}
                onValueChange={setActive}
            >
                <SettingsNavigation />
                <AppRightPanel>
                    <AutostartSettingsProvider>
                    <ScrollArea.Root
                        key={active}
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
                                    <VerticalTabs.Content value={"profiles"}>
                                        <ProfilesTab />
                                    </VerticalTabs.Content>
                                    <VerticalTabs.Content value={"ssh"}>
                                        <SettingsSSH />
                                    </VerticalTabs.Content>
                                    <VerticalTabs.Content value={"advanced"}>
                                        <SettingsAdvanced />
                                    </VerticalTabs.Content>
                                    <VerticalTabs.Content
                                        value={"troubleshooting"}
                                    >
                                        <SettingsTroubleshooting />
                                    </VerticalTabs.Content>
                                    <VerticalTabs.Content value={"about"}>
                                        <SettingsAbout />
                                    </VerticalTabs.Content>
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
                    </AutostartSettingsProvider>
                </AppRightPanel>
            </VerticalTabs>
        </>
    );
};
