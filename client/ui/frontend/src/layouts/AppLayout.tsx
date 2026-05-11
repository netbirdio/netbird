import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";
import { ClientVersionProvider } from "@/modules/auto-update/ClientVersionContext.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

export const AppLayout = () => {
    return (
        <div className={"relative flex h-full flex-col"}>
            <ProfileProvider>
                <DebugBundleProvider>
                    <ClientVersionProvider>
                        <Header />
                        <Outlet />
                    </ClientVersionProvider>
                </DebugBundleProvider>
            </ProfileProvider>
        </div>
    );
};
