import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";
import { NavSectionProvider } from "@/lib/navSection";
import { ViewModeProvider } from "@/lib/viewMode";
import { ClientVersionProvider } from "@/modules/auto-update/ClientVersionContext.tsx";
import { StatusProvider } from "@/modules/daemon-status/StatusContext.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

export const AppLayout = () => {
    return (
        <div className={"relative flex h-full flex-col"}>
            <StatusProvider>
                <ProfileProvider>
                    <DebugBundleProvider>
                        <ClientVersionProvider>
                            <ViewModeProvider>
                                <NavSectionProvider>
                                    <Header />
                                    <Outlet />
                                </NavSectionProvider>
                            </ViewModeProvider>
                        </ClientVersionProvider>
                    </DebugBundleProvider>
                </ProfileProvider>
            </StatusProvider>
        </div>
    );
};
