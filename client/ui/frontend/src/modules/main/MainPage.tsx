import { MainConnectionStatusSwitch } from "@/modules/main/MainConnectionStatusSwitch.tsx";
import { MainHeader } from "@/modules/main/MainHeader.tsx";
import { AppRightPanel } from "@/layouts/AppRightPanel.tsx";
import { Navigation } from "@/modules/main/advanced/Navigation.tsx";
import { cn } from "@/lib/cn";
import { NavSectionProvider, useNavSection } from "@/contexts/NavSectionContext";
import { ViewModeProvider, useViewMode } from "@/contexts/ViewModeContext";
import { NotConnectedState } from "@/components/empty-state/NotConnectedState";
import { useStatus } from "@/contexts/StatusContext";
import { Peers } from "@/modules/main/advanced/peers/Peers";
import { Networks } from "@/modules/main/advanced/networks/Networks";
import { ExitNodes } from "@/modules/main/advanced/exit-nodes/ExitNodes";
import { NetworksProvider } from "@/contexts/NetworksContext";
import {
    PeerDetailProvider,
    usePeerDetail,
} from "@/contexts/PeerDetailContext";
import { PeerDetailPanel } from "@/modules/main/advanced/peers/PeerDetailPanel";

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
    const { viewMode } = useViewMode();
    const isAdvanced = viewMode === "advanced";

    return (
        <div className={"wails-draggable flex flex-1 min-h-0 gap-4r"}>
            <div
                className={"flex flex-col items-center shrink-0 w-[364px]"}
            >
                <MainConnectionStatusSwitch />
            </div>
            {isAdvanced && (
                <NavSectionProvider>
                    <AdvancedAppRightPanel />
                </NavSectionProvider>
            )}
        </div>
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
        >
            <div
                className={cn(
                    "flex-1 min-h-0 min-w-0 flex flex-col",
                    !isConnected && "pointer-events-none select-none",
                )}
                aria-hidden={!isConnected}
            >
                <Navigation />
                <div className={"flex-1 min-h-0 flex flex-col"}>
                    {section === "peers" && <Peers />}
                    {section === "networks" && <Networks />}
                    {section === "exitNode" && <ExitNodes />}
                </div>
            </div>
            {!isConnected && (
                <div
                    className={
                        "absolute inset-0 z-20 flex pointer-events-auto bg-nb-gray-940"
                    }
                >
                    <NotConnectedState />
                </div>
            )}
        </AppRightPanel>
    );
};
