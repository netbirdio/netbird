import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";
import { ClientVersionProvider } from "@/modules/auto-update/ClientVersionContext.tsx";
import { StatusProvider } from "@/modules/daemon-status/StatusContext.tsx";
import { DebugBundleProvider } from "@/modules/debug-bundle/DebugBundleContext.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

// The wide-panel toggle lives in plain React state here so every launch
// starts in the small layout — no localStorage, no cross-machine drift.
// Header drives the toggle; Main reads it via Outlet context to decide
// whether to mount the right-side panel.
export type MainOutletContext = { expanded: boolean };

export const AppLayout = () => {
    const [expanded, setExpanded] = useState(false);
    return (
        <div className={"relative flex h-full flex-col"}>
            <StatusProvider>
                <ProfileProvider>
                    <DebugBundleProvider>
                        <ClientVersionProvider>
                            <Header expanded={expanded} setExpanded={setExpanded} />
                            <Outlet context={{ expanded } satisfies MainOutletContext} />
                        </ClientVersionProvider>
                    </DebugBundleProvider>
                </ProfileProvider>
            </StatusProvider>
        </div>
    );
};
