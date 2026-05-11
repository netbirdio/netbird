import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";
import { UpdateAvailableBanner } from "@/modules/auto-update/UpdateAvailableBanner.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

export const AppLayout = () => {
    return (
        <ProfileProvider>
            <DebugBundleProvider>
                <div className={"relative flex h-full flex-col"}>
                    <Header />
                    <Outlet />
                    <UpdateAvailableBanner />
                </div>
            </DebugBundleProvider>
        </ProfileProvider>
    );
};
