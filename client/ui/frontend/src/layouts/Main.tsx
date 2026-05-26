import { useState } from "react";
import { ConnectionStatusSwitch } from "@/layouts/ConnectionStatusSwitch.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { Navigation, NavSection } from "@/layouts/Navigation.tsx";
import { useViewMode } from "@/lib/viewMode";
import { Peers } from "@/modules/peers/Peers";
import { Networks } from "@/modules/networks/Networks";
import { ExitNodes } from "@/modules/exit-nodes/ExitNodes";
import { NetworksProvider } from "@/modules/networks/NetworksContext";

export const Main = () => {
    const { viewMode } = useViewMode();
    const isAdvanced = viewMode === "advanced";
    const [section, setSection] = useState<NavSection>("peers");

    return (
        <NetworksProvider>
            <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
                {/* Fixed-width column for the connection switch. Navigation
                    is rendered absolutely at the bottom in advanced view so
                    it doesn't reshape the column and shift the switch up. */}
                <div
                    className={
                        "relative flex flex-col items-center shrink-0 w-[348px]"
                    }
                >
                    <ConnectionStatusSwitch />
                    {isAdvanced && (
                        <div className={"absolute inset-x-0 bottom-0 px-1"}>
                            <Navigation
                                active={section}
                                onSelect={setSection}
                            />
                        </div>
                    )}
                </div>
                {isAdvanced && (
                    <MainRightSide>
                        {section === "peers" && <Peers />}
                        {section === "networks" && <Networks />}
                        {section === "exitNode" && <ExitNodes />}
                    </MainRightSide>
                )}
            </div>
        </NetworksProvider>
    );
};
