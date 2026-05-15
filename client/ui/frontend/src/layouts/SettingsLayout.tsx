import { Outlet } from "react-router-dom";
import { ClientVersionProvider } from "@/modules/auto-update/ClientVersionContext.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

// SettingsLayout wraps the Settings screen for use inside its own dedicated
// window. Same provider stack as AppLayout but without the main Header — the
// settings window has its own native title bar and doesn't show the profile
// selector / panel toggle / settings icon.
//
// The 38px placeholder strip at the top accounts for the macOS
// `MacTitleBarHiddenInset` setting in services/windowmanager.go: the native
// title bar is invisible but the traffic-light buttons still float in the
// top-left corner. Without this strip the buttons would overlap the settings
// content. The strip is `wails-draggable` so users can move the window by
// dragging it.
export const SettingsLayout = () => {
    return (
        <div className={"relative flex h-full flex-col"}>
            <ProfileProvider>
                <DebugBundleProvider>
                    <ClientVersionProvider>
                        <div
                            className={
                                "wails-draggable cursor-default select-none h-[38px] shrink-0"
                            }
                        />
                        <Outlet />
                    </ClientVersionProvider>
                </DebugBundleProvider>
            </ProfileProvider>
        </div>
    );
};
