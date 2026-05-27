import { ConnectionStatusSwitch } from "@/layouts/ConnectionStatusSwitch.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { Navigation } from "@/layouts/Navigation.tsx";
import { useNavSection } from "@/lib/navSection";
import { useViewMode } from "@/lib/viewMode";
import { Peers } from "@/modules/peers/Peers";
import { Networks } from "@/modules/networks/Networks";
import { ExitNodes } from "@/modules/exit-nodes/ExitNodes";
import { NetworksProvider } from "@/modules/networks/NetworksContext";
import {
    PeerDetailProvider,
    usePeerDetail,
} from "@/modules/peers/PeerDetailContext";
import { PeerDetailPanel } from "@/modules/peers/PeerDetailPanel";

export const Main = () => {
    return (
        <NetworksProvider>
            <PeerDetailProvider>
                <MainBody />
            </PeerDetailProvider>
        </NetworksProvider>
    );
};

const MainBody = () => {
    const { viewMode } = useViewMode();
    const isAdvanced = viewMode === "advanced";
    const { section } = useNavSection();
    const { selected } = usePeerDetail();

    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div
                className={
                    "flex flex-col items-center shrink-0 w-[348px]"
                }
            >
                <ConnectionStatusSwitch />
            </div>
            {isAdvanced && (
                <MainRightSide
                    overlay={<PeerDetailPanel />}
                    overlayOpen={selected !== null}
                >
                    <Navigation />
                    <div className={"flex-1 min-h-0 flex flex-col"}>
                        {section === "peers" && <Peers />}
                        {section === "networks" && <Networks />}
                        {section === "exitNode" && <ExitNodes />}
                    </div>
                </MainRightSide>
            )}
        </div>
    );
};
