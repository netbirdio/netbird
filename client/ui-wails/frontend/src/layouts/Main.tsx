import { ConnectionStatus } from "@/layouts/ConnectionStatus.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { Navigation } from "@/layouts/Navigation.tsx";
import { Peers } from "@/modules/peers/Peers.tsx";

export const Main = () => {
    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div
                className={
                    "flex flex-col max-w-xs w-full shrink-0 items-center"
                }
            >
                <ConnectionStatus />
                <Navigation peersActive />
            </div>
            <MainRightSide>
                <Peers />
            </MainRightSide>
        </div>
    );
};
