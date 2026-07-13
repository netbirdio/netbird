import { MainConnectionStatusSwitch } from "@/modules/main/MainConnectionStatusSwitch.tsx";
import { MainExitNodeSwitcher } from "@/modules/main/MainExitNodeSwitcher.tsx";
import { MainHeader } from "@/modules/main/MainHeader.tsx";
import { AppRightPanel } from "@/layouts/AppRightPanel.tsx";
import { Navigation } from "@/modules/main/advanced/Navigation.tsx";
import { cn } from "@/lib/cn";
import { NavSectionProvider, useNavSection } from "@/contexts/NavSectionContext";
import { ViewModeProvider, useViewMode } from "@/contexts/ViewModeContext";
import { useEffect } from "react";
import { NotConnectedState } from "@/components/empty-state/NotConnectedState";
import { useStatus } from "@/contexts/StatusContext";
import { Peers } from "@/modules/main/advanced/peers/Peers";
import { Networks } from "@/modules/main/advanced/networks/Networks";
import { NetworksProvider } from "@/contexts/NetworksContext";
import { PeerDetailProvider, usePeerDetail } from "@/contexts/PeerDetailContext";
import { useRestrictions } from "@/contexts/RestrictionsContext";
import { PeerDetailPanel } from "@/modules/main/advanced/peers/PeerDetailPanel";
import { isWindows } from "@/lib/platform.ts";

export const MainPage = () => {
    return (
        <ViewModeProvider>
            <MainHeader />
            <NetworksProvider>
                <PeerDetailProvider>
                    <MainBody />
                </PeerDetailProvider>
            </NetworksProvider>
        </ViewModeProvider>
    );
};

const MainBody = () => {
    const { viewMode, setViewMode } = useViewMode();
    const { mdm, features } = useRestrictions();

    // Force flip the view if MDM disabled advanced
    useEffect(() => {
        if (mdm.disableAdvancedView && viewMode === "advanced") {
            setViewMode("default");
        }
    }, [mdm.disableAdvancedView, viewMode, setViewMode]);

    const isAdvanced = viewMode === "advanced";

    return (
        <main className={"wails-draggable flex min-h-0 flex-1"}>
            {/* Windows narrower width compensates for the OS frame Wails counts differently than macOS.
                See https://github.com/wailsapp/wails/issues/3260 */}
            <div
                className={cn(
                    "relative flex shrink-0 flex-col items-center",
                    isWindows() ? "w-[364px]" : "w-[380px]",
                )}
            >
                <MainConnectionStatusSwitch />
                {!features.disableNetworks && (
                    <div className={"wails-no-draggable absolute bottom-5 left-5 right-5"}>
                        <MainExitNodeSwitcher />
                    </div>
                )}
            </div>
            {isAdvanced && (
                <NavSectionProvider>
                    <AdvancedAppRightPanel />
                </NavSectionProvider>
            )}
        </main>
    );
};

const AdvancedAppRightPanel = () => {
    const { section } = useNavSection();
    const { selected } = usePeerDetail();
    const { status } = useStatus();
    const isConnected = status?.status === "Connected";

    return (
        <AppRightPanel
            overlay={<PeerDetailPanel />}
            overlayOpen={selected !== null}
            className={"m-5 ml-0"}
        >
            <div
                ref={(el) => {
                    if (!el) return;
                    if (isConnected) el.removeAttribute("inert");
                    else el.setAttribute("inert", "");
                }}
                className={cn(
                    "flex min-h-0 min-w-0 flex-1 flex-col",
                    !isConnected && "pointer-events-none select-none",
                )}
                aria-hidden={!isConnected}
            >
                <Navigation />
                <div
                    role={"tabpanel"}
                    id={`nb-tabpanel-${section}`}
                    aria-labelledby={`nb-tab-${section}`}
                    className={"flex min-h-0 flex-1 flex-col"}
                >
                    {section === "peers" && <Peers />}
                    {section === "networks" && <Networks />}
                </div>
            </div>
            {!isConnected && (
                <div className={"pointer-events-auto absolute inset-0 z-20 flex bg-nb-gray-940"}>
                    <NotConnectedState />
                </div>
            )}
        </AppRightPanel>
    );
};
