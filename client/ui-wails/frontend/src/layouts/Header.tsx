import { useLocation, useNavigate } from "react-router-dom";
import { SettingsIcon } from "lucide-react";
import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { cn } from "@/lib/cn";

export const Header = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const settingsActive = location.pathname.startsWith("/settings");

    return (
        <div
            className={
                "pt-4 shrink-0 cursor-default wails-draggable flex items-center justify-end px-4 gap-3 bg-gradient-to-b from-nb-gray-800/15"
            }
        >
            <div className={"ml-20"}>
                <ProfileSelector email={"eduard@netbird.io"} />
            </div>
            <IconButton
                icon={SettingsIcon}
                onClick={() => navigate(settingsActive ? "/" : "/settings")}
                className={cn(
                    settingsActive &&
                        "bg-nb-gray-930 text-nb-gray-200 hover:text-nb-gray-200",
                )}
            />
        </div>
    );
};
