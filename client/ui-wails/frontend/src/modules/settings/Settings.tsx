import { useState } from "react";
import { MainRightSide } from "@/layouts/MainRightSide.tsx";
import {
    SettingsNavigation,
    SettingsSection,
} from "@/modules/settings/SettingsNavigation.tsx";

export const Settings = () => {
    const [active, setActive] = useState<SettingsSection>("general");

    return (
        <div className={"wails-draggable flex flex-1 min-h-0 p-4 gap-4"}>
            <div className={"flex flex-col w-52 shrink-0 items-center"}>
                <SettingsNavigation active={active} onChange={setActive} />
            </div>
            <MainRightSide>{null}</MainRightSide>
        </div>
    );
};
