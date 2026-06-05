import { Outlet } from "react-router-dom";
import { ClientVersionProvider } from "@/contexts/ClientVersionContext.tsx";
import { StatusProvider } from "@/contexts/StatusContext.tsx";
import { DebugBundleProvider } from "@/contexts/DebugBundleContext.tsx";
import { ProfileProvider } from "@/contexts/ProfileContext.tsx";
import { DialogProvider } from "@/contexts/DialogContext.tsx";

// Shared shell for every in-window route (main + settings). Owns the daemon-
// availability gate (via StatusProvider) and the providers every page needs.
// Order matters: SettingsContext depends on ProfileContext; ClientVersionContext
// reads StatusContext events.
//
// Page-specific surface (the main Header, the settings draggable strip,
// view-mode + nav-section providers) lives inside the page components, not here.
export const AppLayout = () => {
    return (
        <div className={"relative flex h-full flex-col"}>
            <DialogProvider>
                <StatusProvider>
                    <ProfileProvider>
                        <DebugBundleProvider>
                            <ClientVersionProvider>
                                <Outlet />
                            </ClientVersionProvider>
                        </DebugBundleProvider>
                    </ProfileProvider>
                </StatusProvider>
            </DialogProvider>
        </div>
    );
};
