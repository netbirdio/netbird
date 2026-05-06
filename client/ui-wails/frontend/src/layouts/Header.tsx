import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { SettingsIcon } from "lucide-react";
import { cn } from "@/lib/cn";

type Props = {
    settingsActive?: boolean;
    onSettingsClick?: () => void;
};

export const Header = ({ settingsActive = false, onSettingsClick }: Props) => {
    return (
        <div className={"w-full justify-between flex mb-12"}>
            <ProfileSelector email={"eduard@netbird.io"} />
            <IconButton
                icon={SettingsIcon}
                onClick={onSettingsClick}
                className={cn(
                    settingsActive &&
                        "bg-nb-gray-930 text-nb-gray-200 hover:text-nb-gray-200",
                )}
            />
        </div>
    );
};
