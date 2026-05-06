import { useState } from "react";
import { MainLeftSide, MainModule } from "@/layouts/MainLeftSide.tsx";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import { Peers } from "@/modules/peers/Peers.tsx";
import { Settings } from "@/modules/settings/Settings.tsx";

type Props = {

};
export const Main = ({}: Props) => {
    const [active, setActive] = useState<MainModule>("peers");

    return (
        <div className={"wails-draggable flex h-full p-4 gap-4 min-h-0"}>
            <MainLeftSide active={active} onChange={setActive} />

            <MainRightSide>
                {active === "peers" ? <Peers /> : <Settings />}
            </MainRightSide>
        </div>

    );
};
