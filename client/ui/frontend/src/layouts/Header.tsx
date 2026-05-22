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
import { Window } from "@wailsio/runtime";
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

// Window dimensions per view. Height matches the Settings window (640) so the
// chrome height is identical across surfaces; width grows from the compact
// 380 default to 900 in advanced.
const VIEW_SIZE: Record<ViewMode, { width: number; height: number }> = {
    default: { width: 380, height: 640 },
    advanced: { width: 900, height: 640 },
};

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
        if (mode === viewMode) return;
        setViewMode(mode);
        const { width, height } = VIEW_SIZE[mode];
        void Window.SetSize(width, height).catch(() => {});
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
            <div className={"flex justify-end wails-no-draggable"}>
                <DropdownMenu modal={false} open={menuOpen} onOpenChange={setMenuOpen}>
                    <DropdownMenuTrigger asChild className={"wails-no-draggable"}>
                        <IconButton
                            icon={MoreVertical}
                            iconClassName={"text-nb-gray-200 wails-no-draggable"}
                        />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent
                        align="end"
                        sideOffset={8}
                        className="min-w-52 data-[state=closed]:!animate-none data-[state=closed]:!duration-0"
                    >
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
