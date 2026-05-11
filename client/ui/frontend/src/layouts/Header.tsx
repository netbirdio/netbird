import { useLocation, useNavigate } from "react-router-dom";
import { ArrowUpCircleIcon, SettingsIcon } from "lucide-react";
import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { Tooltip } from "@/components/Tooltip.tsx";
import { useStatus } from "@/hooks/useStatus";
import { cn } from "@/lib/cn";

export const Header = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const isSettingsPage = location.pathname.startsWith("/settings");
    const { status } = useStatus();
    const updateAvailable = (status?.events ?? []).some((e) =>
        Boolean(e.metadata?.["new_version_available"]),
    );

    return (
        <div
            className={
                "pt-4 shrink-0 cursor-default wails-draggable flex items-center justify-end px-4 gap-3 bg-gradient-to-b from-nb-gray-800/15"
            }
        >
            <div className={"ml-20"}>
                <ProfileSelector email={"eduard@netbird.io"} />
            </div>
            {updateAvailable && (
                <Tooltip content={"Update Available"}>
                    <div className={"relative h-11 w-11 flex items-center justify-center"}>
                        <span
                            className={
                                "animate-ping absolute inline-flex h-[15px] w-[15px] rounded-full bg-netbird opacity-20 pointer-events-none"
                            }
                        />
                        <IconButton
                            icon={ArrowUpCircleIcon}
                            iconClassName={"text-netbird"}
                            onClick={() =>
                                navigate("/settings", { state: { tab: "about" } })
                            }
                            className={"absolute inset-0"}
                        />
                    </div>
                </Tooltip>
            )}
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
