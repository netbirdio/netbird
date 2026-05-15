import { useOutletContext } from "react-router-dom";
import { ConnectionStatusSwitch } from "@/layouts/ConnectionStatusSwitch.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { Navigation } from "@/layouts/Navigation.tsx";
import { Peers } from "@/modules/peers/Peers.tsx";
import type { MainOutletContext } from "@/layouts/AppLayout.tsx";
import { cn } from "@/lib/cn";

export const Main = () => {
    const { expanded } = useOutletContext<MainOutletContext>();
    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div
                className={cn(
                    "flex flex-col w-full shrink-0 items-center",
                    expanded && "max-w-xs",
                )}
            >
                <ConnectionStatusSwitch />
                <Navigation peersActive />
            </div>
            {expanded && (
                <MainRightSide>
                    <Peers />
                </MainRightSide>
            )}
        </div>
    );
};
