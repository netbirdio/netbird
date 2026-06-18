import { forwardRef, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Check, ChevronDown, Settings2, UserCircle } from "lucide-react";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import type { Profile } from "@bindings/services/models.js";
import { Tooltip } from "@/components/Tooltip";
import { useProfile } from "@/contexts/ProfileContext";
import { cn } from "@/lib/cn";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

type ProfileDropdownProps = {
    onManageProfiles?: () => void;
};

const MANAGE_VALUE = "__manage_profiles__";

export const ProfileDropdown = ({ onManageProfiles }: ProfileDropdownProps) => {
    const { t } = useTranslation();
    const { activeProfile, activeProfileId, profiles, switchProfile, loaded } = useProfile();
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const listRef = useRef<HTMLDivElement>(null);

    const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
        if (open) return;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
        }
    };

    const sortedProfiles = [...profiles].sort((a, b) => {
        if (a.id === activeProfileId) return -1;
        if (b.id === activeProfileId) return 1;
        return a.name.localeCompare(b.name);
    });

    const guarded = async (title: string, fn: () => Promise<void>) => {
        if (busy) return;
        setBusy(true);
        try {
            await fn();
        } catch (e) {
            await errorDialog({
                Title: title,
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const handleSelect = (id: string) => {
        setOpen(false);
        if (id === activeProfileId) return;
        void guarded(t("profile.error.switchTitle"), () => switchProfile(id));
    };

    const handleManage = () => {
        setOpen(false);
        onManageProfiles?.();
    };

    if (!loaded) return <ProfileTriggerSkeleton />;

    const hasProfile = !!activeProfileId;
    const displayName = hasProfile ? activeProfile : t("profile.selector.noProfile");

    return (
        <Popover.Root open={open} onOpenChange={setOpen}>
            <Popover.Trigger asChild className={"wails-no-draggable"} disabled={!hasProfile}>
                <ProfileTriggerButton
                    name={displayName}
                    disabled={!hasProfile}
                    onKeyDown={handleTriggerKeyDown}
                />
            </Popover.Trigger>
            <Popover.Portal>
                <Popover.Content
                    align="center"
                    sideOffset={8}
                    collisionPadding={12}
                    onOpenAutoFocus={(e) => {
                        e.preventDefault();
                        listRef.current?.focus();
                    }}
                    className={cn(
                        "z-50 min-w-64 overflow-hidden rounded-lg border border-nb-gray-900 bg-nb-gray-935 p-1 text-nb-gray-200 shadow-lg select-none wails-no-draggable",
                        "data-[state=open]:animate-in data-[state=closed]:animate-out",
                        "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
                        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
                        "data-[side=bottom]:origin-top data-[side=top]:origin-bottom",
                        "data-[side=left]:origin-right data-[side=right]:origin-left",
                        "data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2",
                        "data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
                    )}
                >
                    <Command
                        loop
                        shouldFilter={false}
                        onKeyDown={(e) => e.stopPropagation()}
                        className={"outline-none focus:outline-none focus-visible:outline-none"}
                    >
                        <Command.List
                            ref={listRef}
                            aria-label={t("header.profile.switch")}
                            className={"outline-none focus:outline-none focus-visible:outline-none"}
                        >
                            {sortedProfiles.length > 0 && (
                                <>
                                    <ScrollArea.Root type="auto" className="overflow-hidden -mx-1">
                                        <ScrollArea.Viewport className="max-h-60 px-1">
                                            {sortedProfiles.map((profile) => (
                                                <ProfileRow
                                                    key={profile.id}
                                                    profile={profile}
                                                    isActive={profile.id === activeProfileId}
                                                    onSelect={handleSelect}
                                                />
                                            ))}
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
                                    value={MANAGE_VALUE}
                                    onSelect={handleManage}
                                    disabled={!onManageProfiles}
                                    className={cn(
                                        "flex items-center gap-2 px-2 py-1.5",
                                        "rounded-md outline-none cursor-default text-sm",
                                        "data-[selected=true]:bg-nb-gray-900",
                                        "data-[disabled=true]:opacity-50 data-[disabled=true]:pointer-events-none",
                                    )}
                                >
                                    <Settings2 size={14} aria-hidden="true" className="shrink-0" />
                                    <span className="truncate flex-1">
                                        {t("profile.dropdown.manageProfiles")}
                                    </span>
                                </Command.Item>
                            </div>
                        </Command.List>
                    </Command>
                </Popover.Content>
            </Popover.Portal>
        </Popover.Root>
    );
};

const ProfileTriggerSkeleton = () => (
    <div
        role="status"
        aria-busy="true"
        aria-live="polite"
        className="h-10 flex items-center gap-2 px-3 rounded-lg select-none wails-no-draggable"
    >
        <div
            aria-hidden="true"
            className="size-4 rounded-full bg-nb-gray-900 animate-pulse shrink-0"
        />
        <div aria-hidden="true" className="h-4 w-24 rounded bg-nb-gray-900 animate-pulse" />
    </div>
);

type ProfileTriggerButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    name: string;
};

const ProfileTriggerButton = forwardRef<HTMLButtonElement, ProfileTriggerButtonProps>(
    function ProfileTriggerButton({ name, className, disabled, ...props }, ref) {
        const { t } = useTranslation();
        const Icon = pickProfileIcon(name) ?? UserCircle;
        return (
            <button
                ref={ref}
                type="button"
                disabled={disabled}
                tabIndex={disabled ? -1 : 0}
                aria-label={t("header.profile.switch")}
                aria-haspopup="listbox"
                className={cn(
                    "h-10 flex items-center gap-2 px-3 rounded-lg outline-none cursor-default select-none wails-no-draggable",
                    "text-nb-gray-200 hover:bg-nb-gray-900",
                    "data-[state=open]:bg-nb-gray-900",
                    "disabled:opacity-50 disabled:hover:bg-transparent",
                    "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    "transition-colors duration-150 wails-no-draggable",
                    className,
                )}
                {...props}
            >
                <Icon
                    size={16}
                    aria-hidden="true"
                    className={"text-nb-gray-200 shrink-0 wails-no-draggable"}
                />
                <span className={"text-sm font-medium truncate max-w-[140px] wails-no-draggable"}>
                    {name}
                </span>
                <ChevronDown
                    size={14}
                    aria-hidden="true"
                    className={"text-nb-gray-200 shrink-0 wails-no-draggable"}
                />
            </button>
        );
    },
);

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    onSelect: (id: string) => void;
};

const ProfileRow = ({ profile, isActive, onSelect }: ProfileRowProps) => {
    const showEmail = !!profile.email;
    return (
        <Command.Item
            value={profile.id}
            onSelect={() => onSelect(profile.id)}
            className={cn(
                "flex gap-2 px-2 py-2 pr-3 w-auto last:mb-1",
                "rounded-md outline-none cursor-default text-sm",
                "data-[selected=true]:bg-nb-gray-900",
                showEmail ? "items-start" : "items-center",
            )}
        >
            <div className="flex flex-col min-w-0 flex-1 leading-tight">
                <span className="truncate">{profile.name}</span>
                {showEmail && <TruncatedEmail email={profile.email} />}
            </div>
            {isActive && (
                <Check
                    size={16}
                    aria-hidden="true"
                    className={cn("shrink-0 text-netbird", showEmail && "mt-0.5")}
                />
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
