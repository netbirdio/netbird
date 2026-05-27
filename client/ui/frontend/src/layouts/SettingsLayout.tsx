import { Outlet } from "react-router-dom";
import { ClientVersionProvider } from "@/modules/auto-update/ClientVersionContext.tsx";
import { StatusProvider } from "@/modules/daemon-status/StatusContext.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

// SettingsLayout wraps the Settings screen for use inside its own dedicated
// window. Same provider stack as AppLayout but without the main Header — the
// settings window has its own native title bar and doesn't show the profile
// selector / panel toggle / settings icon.
//
// The h-10 placeholder strip at the top accounts for the macOS
// `MacTitleBarHiddenInset` setting in services/windowmanager.go: the native
// title bar is invisible but the traffic-light buttons still float in the
// top-left corner. The height also mirrors the main window's Header so the
// MainRightSide panel ends up the same height in both windows.
export const SettingsLayout = () => {
    return (
        <div className={"relative flex h-full flex-col select-none"}>
            <StatusProvider>
                <ProfileProvider>
                    <DebugBundleProvider>
                        <ClientVersionProvider>
                            <div
                                className={
                                    "wails-draggable cursor-default select-none h-12 shrink-0"
                                }
                            />
                            <Outlet />
                        </ClientVersionProvider>
                    </DebugBundleProvider>
                </ProfileProvider>
            </StatusProvider>
        </div>
    );
};
