import { ProfileSelector } from "@/components/ProfileSelector.tsx";
import { IconButton } from "@/components/IconButton.tsx";
import { SettingsIcon } from "lucide-react";

export const Header = () => {
    return (
        <div className={"w-full justify-between flex mb-12"}>
            <ProfileSelector />
            <IconButton icon={SettingsIcon} />
        </div>
    );
};
