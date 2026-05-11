import { useLocation, useNavigate } from "react-router-dom";
import { SettingsIcon } from "lucide-react";
import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { UpdateHeaderTrigger } from "@/modules/auto-update/UpdateHeaderTrigger.tsx";
import { cn } from "@/lib/cn";

export const Header = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const isSettingsPage = location.pathname.startsWith("/settings");

    return (
        <div
            className={
                "pt-4 shrink-0 cursor-default wails-draggable flex items-center justify-end px-4 gap-3 bg-gradient-to-b from-nb-gray-800/15"
            }
        >
            <div className={"ml-20"}>
                <ProfileSelector email={"eduard@netbird.io"} />
            </div>
            <UpdateHeaderTrigger />
            <IconButton
                icon={SettingsIcon}
                onClick={() => navigate(isSettingsPage ? "/" : "/settings")}
                className={cn(
                    isSettingsPage &&
                        "bg-nb-gray-910 hover:bg-nb-gray-910 text-nb-gray-200 hover:text-nb-gray-200",
                )}
            />
        </div>
    );
};
