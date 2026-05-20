import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
    Check,
    MoreVertical,
    PanelsRightBottom,
    RectangleVertical,
    Settings,
    type LucideIcon,
} from "lucide-react";
import { WindowManager } from "@bindings/services";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import { IconButton } from "@/components/IconButton";
import { ProfileDropdown } from "@/components/ProfileDropdown";
import { cn } from "@/lib/cn";

type ViewMode = "default" | "advanced";

export const Header = () => {
    const { t } = useTranslation();
    const [menuOpen, setMenuOpen] = useState(false);
    const [viewMode, setViewMode] = useState<ViewMode>("default");

    const openSettings = () => {
        setMenuOpen(false);
        void WindowManager.OpenSettings("").catch(() => {});
    };

    const openManageProfiles = () => {
        void WindowManager.OpenSettings("profiles").catch(() => {});
    };

    const selectMode = (mode: ViewMode) => {
        setMenuOpen(false);
        setViewMode(mode);
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
            <div className={"flex justify-center ml-4"}>
                <ProfileDropdown onManageProfiles={openManageProfiles} />
            </div>
            <div className={"flex justify-end"}>
                <DropdownMenu modal={false} open={menuOpen} onOpenChange={setMenuOpen}>
                    <DropdownMenuTrigger asChild>
                        <IconButton icon={MoreVertical} iconClassName={"text-nb-gray-200"} />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" sideOffset={8} className="min-w-52">
                        <DropdownMenuItem onClick={openSettings}>
                            <div className="flex items-center gap-2">
                                <Settings size={14} />
                                {t("header.menu.settings")}
                            </div>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <ViewModeItem
                            icon={RectangleVertical}
                            label={t("header.menu.defaultView")}
                            selected={viewMode === "default"}
                            onSelect={() => selectMode("default")}
                        />
                        <ViewModeItem
                            icon={PanelsRightBottom}
                            label={t("header.menu.advancedView")}
                            selected={viewMode === "advanced"}
                            onSelect={() => selectMode("advanced")}
                        />
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>
        </div>
    );
};

type ViewModeItemProps = {
    icon: LucideIcon;
    label: string;
    selected: boolean;
    onSelect: () => void;
};

const ViewModeItem = ({ icon: Icon, label, selected, onSelect }: ViewModeItemProps) => (
    <DropdownMenuItem onClick={onSelect}>
        <div className="flex items-center gap-2 w-full">
            <Icon size={14} />
            <span className="flex-1">{label}</span>
            {selected && <Check size={14} className="text-netbird" />}
        </div>
    </DropdownMenuItem>
);
