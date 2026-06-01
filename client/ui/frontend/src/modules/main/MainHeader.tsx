import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import {
    ArrowUpCircleIcon,
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
    DropdownMenuShortcut,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import { IconButton } from "@/components/buttons/IconButton";
import { ProfileDropdown } from "@/modules/profiles/ProfileDropdown";
import { useClientVersion } from "@/contexts/ClientVersionContext";
import { cn } from "@/lib/cn";
import { formatShortcut, useKeyboardShortcut } from "@/hooks/useKeyboardShortcut";
import { useViewMode, type ViewMode } from "@/contexts/ViewModeContext";

const SETTINGS_SHORTCUT = { key: ",", cmd: true } as const;

export const MainHeader = () => {
    const { t } = useTranslation();
    const [menuOpen, setMenuOpen] = useState(false);
    const { viewMode, setViewMode } = useViewMode();
    const { updateAvailable } = useClientVersion();

    const openSettings = useCallback(() => {
        setMenuOpen(false);
        void WindowManager.OpenSettings("").catch(() => {});
    }, []);

    // Mirror the tray's Settings accelerator so the keystroke works while
    // the main window has focus too. The tray's SetAccelerator paints the
    // glyph on macOS/Linux but only fires the menu item — it can't reach the
    // webview's input loop, hence the parallel React-side listener.
    useKeyboardShortcut(SETTINGS_SHORTCUT, openSettings);

    const openAbout = () => {
        setMenuOpen(false);
        void WindowManager.OpenSettings("about").catch(() => {});
    };

    const openManageProfiles = () => {
        void WindowManager.OpenSettings("profiles").catch(() => {});
    };

    const selectMode = (mode: ViewMode) => {
        setMenuOpen(false);
        setViewMode(mode);
    };

    const profileSlot = <ProfileDropdown onManageProfiles={openManageProfiles} />;

    const settingsSlot = (
        <div className={"relative"}>
            <DropdownMenu modal={false} open={menuOpen} onOpenChange={setMenuOpen}>
                <DropdownMenuTrigger asChild className={"wails-no-draggable"}>
                    <IconButton
                        icon={MoreVertical}
                        iconClassName={"text-nb-gray-200 wails-no-draggable"}
                        className={"select-none"}
                    />
                </DropdownMenuTrigger>
                <DropdownMenuContent
                    align="end"
                    sideOffset={8}
                    className="min-w-52 select-none data-[state=closed]:!animate-none data-[state=closed]:!duration-0"
                >
                    {updateAvailable && (
                        <>
                            <DropdownMenuItem onClick={openAbout}>
                                <div className="flex items-center gap-2">
                                    <ArrowUpCircleIcon size={14} className={"text-netbird"} />
                                    <span className={"text-netbird"}>
                                        {t("header.menu.updateAvailable")}
                                    </span>
                                </div>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                        </>
                    )}
                    <DropdownMenuItem onClick={openSettings}>
                        <div className="flex items-center gap-2 w-full">
                            <Settings size={14} />
                            <span className="flex-1">{t("header.menu.settings")}</span>
                            <DropdownMenuShortcut>
                                {formatShortcut(SETTINGS_SHORTCUT)}
                            </DropdownMenuShortcut>
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
            {updateAvailable && (
                <span
                    className={
                        "pointer-events-none absolute top-1.5 right-1.5 flex h-2.5 w-2.5 items-center justify-center"
                    }
                >
                    <span
                        className={
                            "absolute inset-0 rounded-full bg-netbird opacity-60 animate-ping"
                        }
                    />
                    <span className={"relative h-1.5 w-1.5 rounded-full bg-netbird"} />
                </span>
            )}
        </div>
    );

    // The inner grid is locked to 356px (the default-mode content width:
    // 380px window − 12px px-3 each side). It stays left-anchored regardless
    // of window size, so the profile keeps the exact same absolute X
    // position when the user flips to advanced view. The settings button is
    // pulled out as an absolute, right-anchored element so it tracks the
    // window's right edge in both modes.
    // Header height matches the Settings window's top traffic-light strip
    // so the right panel ends up the same height in both windows. The h-10
    // of the inner buttons (profile trigger, more-vertical) defines the
    // natural height; the strip in SettingsLayout is sized to mirror it.
    return (
        <div
            className={cn(
                "shrink-0 cursor-default wails-draggable relative",
                "flex items-center h-12 top-2.5",
            )}
        >
            <div className={"grid grid-cols-3 items-center w-[380px] shrink-0"}>
                <div />
                <div className={"flex justify-center ml-4"}>{profileSlot}</div>
                <div />
            </div>
            <div className={"absolute right-[0.98rem] top-1/2 -translate-y-1/2"}>
                {settingsSlot}
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
