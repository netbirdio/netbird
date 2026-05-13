import { useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Dialogs } from "@wailsio/runtime";
import { ChevronDown, MoreVertical, PlusCircle, Search, Trash2, UserMinus } from "lucide-react";
import type { Profile } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { generateColorFromString } from "@/lib/color";
import { NewProfileDialog } from "@/components/NewProfileDialog";
import { useProfile } from "@/modules/profile/ProfileContext.tsx";

const DEFAULT_PROFILE = "default";

export const ProfileSelector = () => {
    const {
        profiles,
        activeProfile,
        loaded,
        switchProfile,
        addProfile,
        removeProfile,
        logoutProfile,
    } = useProfile();

    const [open, setOpen] = useState(false);
    const [newOpen, setNewOpen] = useState(false);
    const [busy, setBusy] = useState(false);

    const selected =
        profiles.find((p) => p.name === activeProfile) ??
        profiles.find((p) => p.isActive) ??
        profiles[0];

    const sorted = [...profiles].sort((a, b) => a.name.localeCompare(b.name));

    const guarded = async (title: string, fn: () => Promise<void>) => {
        if (busy) return;
        setBusy(true);
        try {
            await fn();
        } catch (e) {
            await Dialogs.Error({
                Title: title,
                Message: e instanceof Error ? e.message : String(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const handleSelect = (name: string) => {
        setOpen(false);
        if (name === activeProfile) return;
        void guarded("Switch Profile Failed", () => switchProfile(name));
    };

    const handleDeregister = async (name: string) => {
        const result = await Dialogs.Warning({
            Title: "Deregister Profile",
            Message: `Are you sure you want to deregister "${name}"? You will need to log in again to use it.`,
            Buttons: [
                { Label: "Cancel", IsCancel: true },
                { Label: "Deregister", IsDefault: true },
            ],
        });
        if (result !== "Deregister") return;
        void guarded("Deregister Profile Failed", () => logoutProfile(name));
    };

    const handleDelete = async (name: string) => {
        if (name === DEFAULT_PROFILE) return;
        const result = await Dialogs.Warning({
            Title: "Delete Profile",
            Message: `Are you sure you want to delete "${name}"? This action cannot be undone.`,
            Buttons: [
                { Label: "Cancel", IsCancel: true },
                { Label: "Delete", IsDefault: true },
            ],
        });
        if (result !== "Delete") return;
        void guarded("Delete Profile Failed", () => removeProfile(name));
    };

    const handleNewProfile = () => {
        setOpen(false);
        setNewOpen(true);
    };

    const handleCreateProfile = (name: string) => {
        void guarded("Create Profile Failed", () => addProfile(name));
    };

    const displayName = selected?.name ?? (loaded ? "No profile" : "Loading...");
    const initial = (selected?.name ?? "?").charAt(0).toUpperCase();
    const initialColor = generateColorFromString(selected?.name);

    return (
        <>
            <Popover.Root open={open} onOpenChange={setOpen}>
                <Popover.Trigger asChild>
                    <button
                        type="button"
                        className={
                            "h-11 rounded-md text-nb-gray-300 flex items-center gap-1 text-xs hover:bg-nb-gray-930 data-[state=open]:bg-nb-gray-930 px-2 -mx-1 outline-none cursor-default transition-colors duration-150"
                        }
                    >
                        <div
                            className={cn(
                                "flex items-center justify-center bg-nb-gray-900 rounded-md text-xs font-semibold h-6 w-6",
                            )}
                            style={{ color: initialColor }}
                        >
                            {initial}
                        </div>
                        <div
                            className={
                                "whitespace-nowrap flex flex-col ml-1 text-left justify-center"
                            }
                        >
                            <span className={"leading-none text-nb-gray-200 font-semibold"}>
                                {displayName}
                            </span>
                        </div>
                        <ChevronDown size={14} className={"ml-2 mr-2"} />
                    </button>
                </Popover.Trigger>

                <Popover.Portal>
                    <Popover.Content
                        align="end"
                        sideOffset={6}
                        className={cn(
                            "w-72 rounded-md border border-nb-gray-900 bg-nb-gray-930 shadow-lg",
                            "p-1 z-50 origin-[var(--radix-popover-content-transform-origin)]",
                            "data-[state=open]:animate-in data-[state=closed]:animate-out",
                            "data-[state=open]:fade-in-0 data-[state=closed]:fade-out-0",
                            "data-[state=open]:zoom-in-95 data-[state=closed]:zoom-out-95",
                            "data-[side=bottom]:slide-in-from-top-1",
                            "data-[side=top]:slide-in-from-bottom-1",
                            "duration-150 ease-out",
                        )}
                        onCloseAutoFocus={(e) => e.preventDefault()}
                    >
                        <Command
                            loop
                            className={cn(
                                "flex flex-col",
                                "[&_[cmdk-input-wrapper]]:flex [&_[cmdk-input-wrapper]]:items-center",
                            )}
                        >
                            <div className="px-1 pb-1">
                                <div className="group flex items-center gap-2 px-2 h-8">
                                    <Search size={12} className="text-nb-gray-300 shrink-0" />
                                    <Command.Input
                                        autoFocus
                                        placeholder="Search profile by name..."
                                        className={cn(
                                            "w-full bg-transparent text-xs text-nb-gray-200 placeholder:text-nb-gray-400",
                                            "outline-none border-none",
                                        )}
                                    />
                                </div>
                            </div>

                            <ScrollArea.Root type="auto" className="overflow-hidden -mx-1">
                                <ScrollArea.Viewport className="max-h-64 px-1 pb-1">
                                    <Command.List>
                                        <Command.Empty>
                                            <div className="flex flex-col items-center text-center px-4 pt-2 pb-3">
                                                <h3 className="text-xs font-semibold text-nb-gray-200">
                                                    No Profiles Found
                                                </h3>
                                                <p className="text-[0.7rem] leading-snug text-nb-gray-400 mt-1 text-balance">
                                                    Try a different search term or create a new
                                                    profile.
                                                </p>
                                            </div>
                                        </Command.Empty>

                                        {sorted.map((profile) => (
                                            <ProfileRow
                                                key={profile.name}
                                                profile={profile}
                                                selected={profile.name === activeProfile}
                                                onSelect={() => handleSelect(profile.name)}
                                                onDeregister={() => handleDeregister(profile.name)}
                                                onDelete={() => handleDelete(profile.name)}
                                                deletable={profile.name !== DEFAULT_PROFILE}
                                            />
                                        ))}
                                    </Command.List>
                                </ScrollArea.Viewport>
                                <ScrollArea.Scrollbar
                                    orientation="vertical"
                                    className={cn(
                                        "flex select-none touch-none transition-colors",
                                        "w-1.5 bg-transparent py-1",
                                    )}
                                >
                                    <ScrollArea.Thumb className="flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative" />
                                </ScrollArea.Scrollbar>
                            </ScrollArea.Root>

                            <div className="h-px bg-nb-gray-920 -mx-1 my-1" />

                            <button
                                type="button"
                                onClick={handleNewProfile}
                                className={cn(
                                    "w-full flex items-center gap-2 pl-2 pr-3 py-1.5 rounded-md cursor-default outline-none",
                                    "text-netbird hover:bg-nb-gray-910",
                                )}
                            >
                                <div
                                    className={
                                        "h-6 w-6 flex items-center justify-center rounded-md bg-nb-gray-900 shrink-0"
                                    }
                                >
                                    <PlusCircle size={12} className="text-netbird" />
                                </div>
                                <span className="text-xs font-semibold">New Profile</span>
                            </button>
                        </Command>
                    </Popover.Content>
                </Popover.Portal>
            </Popover.Root>
            <NewProfileDialog
                open={newOpen}
                onOpenChange={setNewOpen}
                onCreate={handleCreateProfile}
            />
        </>
    );
};

type ProfileRowProps = {
    profile: Profile;
    selected: boolean;
    onSelect: () => void;
    onDeregister: () => void;
    onDelete: () => void;
    deletable: boolean;
};

const ProfileRow = ({
    profile,
    selected,
    onSelect,
    onDeregister,
    onDelete,
    deletable,
}: ProfileRowProps) => {
    const [menuOpen, setMenuOpen] = useState(false);
    const initial = profile.name.charAt(0).toUpperCase();
    const initialColor = generateColorFromString(profile.name);

    return (
        <Command.Item
            value={profile.name}
            onSelect={() => onSelect()}
            className={cn(
                "group flex items-center gap-2 pl-2 pr-3 py-1.5 rounded-md cursor-default outline-none",
                "data-[selected=true]:bg-nb-gray-910",
                selected && "bg-nb-gray-910",
            )}
        >
            <div
                className={cn(
                    "h-6 w-6 flex items-center justify-center rounded-md text-[0.65rem] font-semibold shrink-0 bg-nb-gray-900",
                    "group-data-[selected=true]:bg-nb-gray-850",
                    selected && "bg-nb-gray-850",
                )}
                style={{ color: initialColor }}
            >
                {initial}
            </div>
            <span
                className={cn(
                    "flex-1 truncate text-xs",
                    selected ? "text-nb-gray-200 font-semibold" : "text-nb-gray-200",
                )}
            >
                {profile.name}
            </span>

            <DropdownMenu.Root open={menuOpen} onOpenChange={setMenuOpen} modal={false}>
                <DropdownMenu.Trigger asChild>
                    <button
                        type="button"
                        onClick={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                        }}
                        onPointerDown={(e) => e.stopPropagation()}
                        onKeyDown={(e) => e.stopPropagation()}
                        className={cn(
                            "h-6 w-6 flex items-center justify-center rounded text-nb-gray-400 cursor-default",
                            "hover:bg-nb-gray-800 hover:text-nb-gray-200 outline-none",
                            "data-[state=open]:bg-nb-gray-800 data-[state=open]:text-nb-gray-200",
                        )}
                        aria-label="More options"
                    >
                        <MoreVertical size={14} />
                    </button>
                </DropdownMenu.Trigger>
                <DropdownMenu.Portal>
                    <DropdownMenu.Content
                        side="bottom"
                        align="end"
                        sideOffset={4}
                        onClick={(e) => e.stopPropagation()}
                        onPointerDown={(e) => e.stopPropagation()}
                        className={cn(
                            "w-44 rounded-md border border-nb-gray-850 bg-nb-gray-910 shadow-lg p-1 z-50",
                        )}
                    >
                        <DropdownMenu.Item
                            onSelect={(e) => {
                                e.preventDefault();
                                onDeregister();
                                setMenuOpen(false);
                            }}
                            className={cn(
                                "flex items-center gap-2 px-2 py-1.5 rounded-md cursor-default outline-none font-medium",
                                "text-xs text-nb-gray-200 data-[highlighted]:bg-nb-gray-850",
                            )}
                        >
                            <UserMinus size={14} className="text-nb-gray-300" />
                            <span>Deregister</span>
                        </DropdownMenu.Item>
                        <DropdownMenu.Item
                            disabled={!deletable}
                            onSelect={(e) => {
                                e.preventDefault();
                                if (!deletable) return;
                                onDelete();
                                setMenuOpen(false);
                            }}
                            className={cn(
                                "flex items-center gap-2 px-2 py-1.5 rounded-md cursor-default outline-none font-medium",
                                "text-xs data-[highlighted]:bg-nb-gray-850",
                                deletable
                                    ? "text-red-500"
                                    : "text-nb-gray-500 cursor-not-allowed",
                            )}
                        >
                            <Trash2 size={14} />
                            <span>Delete Profile</span>
                        </DropdownMenu.Item>
                    </DropdownMenu.Content>
                </DropdownMenu.Portal>
            </DropdownMenu.Root>
        </Command.Item>
    );
};
