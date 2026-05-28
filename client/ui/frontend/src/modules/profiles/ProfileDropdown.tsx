import { forwardRef, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Dialogs } from "@wailsio/runtime";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Check, ChevronDown, PlusCircle, Settings2, UserCircle } from "lucide-react";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import type { Profile } from "@bindings/services/models.js";
import { ProfileCreationModal } from "@/modules/profiles/ProfileCreationModal";
import { Tooltip } from "@/components/Tooltip";
import { useProfile } from "@/contexts/ProfileContext";
import { cn } from "@/lib/cn";
import { formatErrorMessage } from "@/lib/errors";

type ProfileDropdownProps = {
    onManageProfiles?: () => void;
};

const ADD_VALUE = "__add_profile__";
const MANAGE_VALUE = "__manage_profiles__";

export const ProfileDropdown = ({ onManageProfiles }: ProfileDropdownProps) => {
    const { t } = useTranslation();
    const { activeProfile, profiles, addProfile, switchProfile } = useProfile();
    const [open, setOpen] = useState(false);
    const [newProfileOpen, setNewProfileOpen] = useState(false);
    const [busy, setBusy] = useState(false);

    const sortedProfiles = [...profiles].sort((a, b) => {
        if (a.name === activeProfile) return -1;
        if (b.name === activeProfile) return 1;
        return a.name.localeCompare(b.name);
    });

    const guarded = async (title: string, fn: () => Promise<void>) => {
        if (busy) return;
        setBusy(true);
        try {
            await fn();
        } catch (e) {
            await Dialogs.Error({
                Title: title,
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const handleSelect = (name: string) => {
        setOpen(false);
        if (name === activeProfile) return;
        void guarded(t("profile.error.switchTitle"), () => switchProfile(name));
    };

    const handleAdd = () => {
        setOpen(false);
        setNewProfileOpen(true);
    };

    const handleManage = () => {
        setOpen(false);
        onManageProfiles?.();
    };

    const handleCreateProfile = async (name: string) => {
        try {
            await addProfile(name);
            await switchProfile(name);
        } catch (e) {
            await Dialogs.Error({
                Title: t("profile.error.createTitle"),
                Message: formatErrorMessage(e),
            });
        }
    };

    const displayName = activeProfile || t("profile.selector.loading");

    return (
        <>
            <Popover.Root open={open} onOpenChange={setOpen}>
                <Popover.Trigger asChild className={"wails-no-draggable"}>
                    <ProfileTriggerButton name={displayName} />
                </Popover.Trigger>
                <Popover.Portal>
                    <Popover.Content
                        align="center"
                        sideOffset={8}
                        collisionPadding={12}
                        onOpenAutoFocus={(e) => e.preventDefault()}
                        className={cn(
                            "z-50 min-w-64 overflow-hidden rounded-lg border border-nb-gray-900 bg-nb-gray-935 p-1 text-nb-gray-200 shadow-lg select-none wails-no-draggable",
                            "data-[state=open]:animate-in data-[state=closed]:animate-out",
                            "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
                            "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
                            "data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2",
                            "data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
                        )}
                    >
                        <Command loop shouldFilter={false} onKeyDown={(e) => e.stopPropagation()}>
                            {sortedProfiles.length > 0 && (
                                <>
                                    <ScrollArea.Root type="auto" className="overflow-hidden -mx-1">
                                        <ScrollArea.Viewport className="max-h-60 px-1">
                                            <Command.List>
                                                {sortedProfiles.map((profile) => (
                                                    <ProfileRow
                                                        key={profile.name}
                                                        profile={profile}
                                                        isActive={profile.name === activeProfile}
                                                        onSelect={handleSelect}
                                                    />
                                                ))}
                                            </Command.List>
                                        </ScrollArea.Viewport>
                                        <ScrollArea.Scrollbar
                                            orientation="vertical"
                                            className={cn(
                                                "flex select-none touch-none transition-colors",
                                                "w-1.5 bg-transparent",
                                            )}
                                        >
                                            <ScrollArea.Thumb className="flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700 relative" />
                                        </ScrollArea.Scrollbar>
                                    </ScrollArea.Root>
                                    <div className="-mx-1 h-px bg-nb-gray-910" />
                                </>
                            )}

                            <div className={"pt-1"}>
                                <Command.Item
                                    value={ADD_VALUE}
                                    onSelect={handleAdd}
                                    className={cn(
                                        "flex items-center gap-2 px-2 py-1.5 my-0.5",
                                        "rounded-md outline-none cursor-default text-sm",
                                        "data-[selected=true]:bg-nb-gray-900",
                                    )}
                                >
                                    <PlusCircle size={14} className="shrink-0" />
                                    <span className="truncate flex-1">
                                        {t("profile.dropdown.addProfile")}
                                    </span>
                                </Command.Item>
                                <Command.Item
                                    value={MANAGE_VALUE}
                                    onSelect={handleManage}
                                    disabled={!onManageProfiles}
                                    className={cn(
                                        "flex items-center gap-2 px-2 py-1.5 my-0.5",
                                        "rounded-md outline-none cursor-default text-sm",
                                        "data-[selected=true]:bg-nb-gray-900",
                                        "data-[disabled=true]:opacity-50 data-[disabled=true]:pointer-events-none",
                                    )}
                                >
                                    <Settings2 size={14} className="shrink-0" />
                                    <span className="truncate flex-1">
                                        {t("profile.dropdown.manageProfiles")}
                                    </span>
                                </Command.Item>
                            </div>
                        </Command>
                    </Popover.Content>
                </Popover.Portal>
            </Popover.Root>
            <ProfileCreationModal
                open={newProfileOpen}
                onOpenChange={setNewProfileOpen}
                onCreate={handleCreateProfile}
            />
        </>
    );
};

type ProfileTriggerButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    name: string;
};

const ProfileTriggerButton = forwardRef<HTMLButtonElement, ProfileTriggerButtonProps>(
    function ProfileTriggerButton({ name, className, ...props }, ref) {
        const Icon = pickProfileIcon(name) ?? UserCircle;
        return (
            <button
                ref={ref}
                type="button"
                className={cn(
                    "h-10 flex items-center gap-2 px-3 rounded-lg outline-none cursor-default select-none wails-no-draggable",
                    "text-nb-gray-200 hover:bg-nb-gray-900",
                    "data-[state=open]:bg-nb-gray-900",
                    "transition-colors duration-150 wails-no-draggable",
                    className,
                )}
                {...props}
            >
                <Icon size={16} className={"text-nb-gray-200 shrink-0 wails-no-draggable"} />
                <span className={"text-sm font-medium truncate max-w-[140px] wails-no-draggable"}>
                    {name}
                </span>
                <ChevronDown size={14} className={"text-nb-gray-200 shrink-0 wails-no-draggable"} />
            </button>
        );
    },
);

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    onSelect: (name: string) => void;
};

const ProfileRow = ({ profile, isActive, onSelect }: ProfileRowProps) => {
    const showEmail = !!profile.email;
    const Icon = pickProfileIcon(profile.name) ?? UserCircle;
    return (
        <Command.Item
            value={profile.name}
            onSelect={() => onSelect(profile.name)}
            className={cn(
                "flex gap-2 px-2 py-2 pr-3 my-0.5 first:mt-0 last:mb-1 w-auto",
                "rounded-md outline-none cursor-default text-sm",
                "data-[selected=true]:bg-nb-gray-900",
                showEmail ? "items-start" : "items-center",
            )}
        >
            <Icon size={14} className={cn("shrink-0", showEmail && "mt-0.5")} />
            <div className="flex flex-col min-w-0 flex-1 leading-tight">
                <span className="truncate">{profile.name}</span>
                {showEmail && <TruncatedEmail email={profile.email!} />}
            </div>
            {isActive && (
                <Check size={16} className={cn("shrink-0 text-netbird", showEmail && "mt-0.5")} />
            )}
        </Command.Item>
    );
};

const TruncatedEmail = ({ email }: { email: string }) => {
    const ref = useRef<HTMLSpanElement>(null);
    const [overflowing, setOverflowing] = useState(false);

    useLayoutEffect(() => {
        const el = ref.current;
        if (!el) return;
        setOverflowing(el.scrollWidth > el.clientWidth);
    }, [email]);

    const span = (
        <span ref={ref} className="text-xs mt-0.5 text-nb-gray-300 truncate max-w-[180px]">
            {email}
        </span>
    );
    if (!overflowing) return span;
    return <Tooltip content={email}>{span}</Tooltip>;
};
