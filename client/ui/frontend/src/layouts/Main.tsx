import { ConnectionStatusSwitch } from "@/layouts/ConnectionStatusSwitch.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { useViewMode } from "@/lib/viewMode";
import { Peers } from "@/modules/peers/Peers";

export const Main = () => {
    const { viewMode } = useViewMode();
    const isAdvanced = viewMode === "advanced";

    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            {/* Fixed-width column for the connection switch — same in both
                default and advanced view so the NetBird logo doesn't shift
                horizontally when the window grows. In default view the
                inner row is 348px so the column fills it; in advanced view
                the column sits on the left with Peers in the remaining
                space. */}
            <div className={"flex flex-col items-center shrink-0 w-[348px]"}>
                <ConnectionStatusSwitch />
            </div>
            {isAdvanced && (
                <MainRightSide>
                    <Peers />
                </MainRightSide>
            )}
        </div>
    );
};
