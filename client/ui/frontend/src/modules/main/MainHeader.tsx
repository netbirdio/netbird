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
import { useRestrictions } from "@/contexts/RestrictionsContext";
import { isWindows } from "@/lib/platform.ts";

const SETTINGS_SHORTCUT = { key: ",", cmd: true } as const;

export const MainHeader = () => {
    const { t } = useTranslation();
    const [menuOpen, setMenuOpen] = useState(false);
    const { viewMode, setViewMode } = useViewMode();
    const { updateAvailable } = useClientVersion();
    const { mdm, features } = useRestrictions();

    const openSettings = useCallback(() => {
        setMenuOpen(false);
        WindowManager.OpenSettings("").catch((err: unknown) =>
            console.error("open settings window failed", err),
        );
    }, []);

    useKeyboardShortcut(SETTINGS_SHORTCUT, openSettings);

    const openAbout = () => {
        setMenuOpen(false);
        WindowManager.OpenSettings("about").catch((err: unknown) =>
            console.error("open settings (about) window failed", err),
        );
    };

    const openManageProfiles = () => {
        WindowManager.OpenSettings("profiles").catch((err: unknown) =>
            console.error("open settings (profiles) window failed", err),
        );
    };

    const selectMode = (mode: ViewMode) => {
        setMenuOpen(false);
        setViewMode(mode);
    };

    const profileSlot = features.disableProfiles ? null : (
        <ProfileDropdown onManageProfiles={openManageProfiles} />
    );

    const settingsSlot = (
        <div className={"relative"}>
            <DropdownMenu modal={false} open={menuOpen} onOpenChange={setMenuOpen}>
                <DropdownMenuTrigger asChild className={"wails-no-draggable"}>
                    <IconButton
                        icon={MoreVertical}
                        iconClassName={"text-nb-gray-200 wails-no-draggable"}
                        className={"select-none"}
                        aria-label={t("header.menu.open")}
                        aria-haspopup={"menu"}
                        aria-expanded={menuOpen}
                    />
                </DropdownMenuTrigger>
                <DropdownMenuContent
                    align={"end"}
                    sideOffset={8}
                    className={
                        "min-w-52 select-none data-[state=closed]:!animate-none data-[state=closed]:!duration-0"
                    }
                >
                    {updateAvailable && (
                        <>
                            <DropdownMenuItem onClick={openAbout}>
                                <div className={"flex items-center gap-2"}>
                                    <ArrowUpCircleIcon
                                        size={14}
                                        className={"text-netbird"}
                                        aria-hidden={"true"}
                                    />
                                    <span className={"text-netbird"}>
                                        {t("header.menu.updateAvailable")}
                                    </span>
                                </div>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                        </>
                    )}
                    <DropdownMenuItem onClick={openSettings}>
                        <div className={"flex w-full items-center gap-2"}>
                            <Settings size={14} aria-hidden={"true"} />
                            <span className={"flex-1"}>{t("header.menu.settings")}</span>
                            <DropdownMenuShortcut>
                                {formatShortcut(SETTINGS_SHORTCUT)}
                            </DropdownMenuShortcut>
                        </div>
                    </DropdownMenuItem>
                    {!mdm.disableAdvancedView && (
                        <>
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
                        </>
                    )}
                </DropdownMenuContent>
            </DropdownMenu>
            {updateAvailable && (
                <span
                    aria-hidden={"true"}
                    className={
                        "pointer-events-none absolute right-1.5 top-1.5 flex h-2.5 w-2.5 items-center justify-center"
                    }
                >
                    <span
                        className={
                            "absolute inset-0 animate-ping rounded-full bg-netbird opacity-60"
                        }
                    />
                    <span className={"relative h-1.5 w-1.5 rounded-full bg-netbird"} />
                </span>
            )}
        </div>
    );

    return (
        <header
            className={cn(
                "wails-draggable relative z-10 shrink-0 cursor-default",
                "top-3 flex h-12 items-center",
            )}
        >
            {/* Windows narrower width compensates for the OS frame Wails counts differently than macOS.
                See https://github.com/wailsapp/wails/issues/3260 */}
            <div
                className={cn(
                    "grid shrink-0 grid-cols-3 items-center",
                    isWindows() ? "w-[364px]" : "w-[380px]",
                )}
            >
                <div />
                <div className={"ml-4 flex justify-center"}>{profileSlot}</div>
                <div />
            </div>
            <div className={"absolute right-[1.3rem] top-1/2 -translate-y-1/2"}>{settingsSlot}</div>
        </header>
    );
};

type ViewModeItemProps = {
    icon: LucideIcon;
    label: string;
    selected: boolean;
    onSelect: () => void;
};

const ViewModeItem = ({ icon: Icon, label, selected, onSelect }: ViewModeItemProps) => (
    <DropdownMenuItem onClick={onSelect} role={"menuitemradio"} aria-checked={selected}>
        <div className={"flex w-full items-center gap-2"}>
            <Icon size={14} aria-hidden={"true"} />
            <span className={"flex-1"}>{label}</span>
            {selected && <Check size={14} className={"text-netbird"} aria-hidden={"true"} />}
        </div>
    </DropdownMenuItem>
);
