import { SettingsIcon } from "lucide-react";
import { WindowManager } from "@bindings/services";
import { IconButton } from "@/components/IconButton";
import { ProfileDropdown } from "@/components/ProfileDropdown";
import { cn } from "@/lib/cn";

export const Header = () => {
    const openSettings = () => {
        void WindowManager.OpenSettings().catch(() => {});
    };

    return (
        <div
            className={cn(
                "shrink-0 cursor-default wails-draggable grid grid-cols-3 items-center",
                //"bg-gradient-to-b from-nb-gray-850/30",
                //"bg-nb-gray-935 border border-b border-nb-gray-850",
                "py-3 px-3",
            )}
        >
            <div />
            <div className={"flex justify-center ml-3"}>
                <ProfileDropdown />
            </div>
            <div className={"flex justify-end"}>
                <IconButton
                    icon={SettingsIcon}
                    iconClassName={"text-nb-gray-200"}
                    onClick={openSettings}
                />
            </div>
        </div>
    );
};
