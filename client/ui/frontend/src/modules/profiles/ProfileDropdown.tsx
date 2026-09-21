import { forwardRef, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Popover from "@radix-ui/react-popover";
import * as ScrollArea from "@radix-ui/react-scroll-area";
import { Command } from "cmdk";
import { Check, ChevronDown, Lock, Settings2, UserCircle } from "lucide-react";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import type { Profile } from "@bindings/services/models.js";
import { Tooltip } from "@/components/Tooltip";
import { useProfile } from "@/contexts/ProfileContext";
import { useFocusVisible } from "@/hooks/useFocusVisible";
import { cn } from "@/lib/cn";
import { errorDialogFor } from "@/lib/errors";

type ProfileDropdownProps = {
    onManageProfiles?: () => void;
};

const MANAGE_VALUE = "__manage_profiles__";

export const ProfileDropdown = ({ onManageProfiles }: ProfileDropdownProps) => {
    const { t } = useTranslation();
    const {
        activeProfile,
        activeProfileId,
        activeProfileForeign,
        profiles,
        switchProfile,
        loaded,
    } = useProfile();
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
            await errorDialogFor(title, e);
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
    const activeFromList = profiles.find((p) => p.id === activeProfileId)?.name;
    const noProfile = t("profile.selector.noProfile");
    let displayName = noProfile;
    if (activeProfileForeign) {
        displayName = t("profile.ownedByAnother.name");
    } else if (hasProfile) {
        // The daemon's name is a fallback for a profile the listing did not
        // carry, and both are empty when it reports no active profile at all.
        displayName = activeFromList || activeProfile || noProfile;
    }

    const trigger = (
        <Popover.Trigger asChild className={"wails-no-draggable"} disabled={!hasProfile}>
            <ProfileTriggerButton
                name={displayName}
                locked={activeProfileForeign}
                disabled={!hasProfile}
                onKeyDown={handleTriggerKeyDown}
            />
        </Popover.Trigger>
    );

    return (
        <Popover.Root open={open} onOpenChange={setOpen}>
            {activeProfileForeign ? (
                // The label has to stay short enough not to truncate in the
                // header, so the sentence that explains the state lives here
                // and in the notice above the list.
                <Tooltip
                    content={t("profile.ownedByAnother.hint")}
                    suppressed={open}
                    keepOpenOnClick={false}
                    contentClassName={cn(
                        "max-w-[16rem] leading-snug",
                        "rounded-md border border-nb-gray-800 bg-white px-2 py-1.5",
                        "dark:border-nb-gray-850 dark:bg-nb-gray-900",
                    )}
                >
                    {trigger}
                </Tooltip>
            ) : (
                trigger
            )}
            <Popover.Portal>
                <Popover.Content
                    align={"center"}
                    sideOffset={8}
                    collisionPadding={12}
                    onOpenAutoFocus={(e) => {
                        e.preventDefault();
                        listRef.current?.focus();
                    }}
                    className={cn(
                        "wails-no-draggable z-50 min-w-64 select-none overflow-hidden rounded-lg border border-nb-gray-800 bg-nb-gray-950 p-1 text-nb-gray-200 shadow-lg dark:border-nb-gray-900 dark:bg-nb-gray-935",
                        "data-[state=open]:animate-in data-[state=closed]:animate-out",
                        "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
                        "data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95",
                        "data-[side=bottom]:origin-top data-[side=top]:origin-bottom",
                        "data-[side=left]:origin-right data-[side=right]:origin-left",
                        "data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2",
                        "data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
                    )}
                >
                    {activeProfileForeign && <ForeignProfileNotice />}
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
                                    <ScrollArea.Root
                                        type={"auto"}
                                        className={"-mx-1 overflow-hidden"}
                                    >
                                        <ScrollArea.Viewport className={"max-h-60 px-1"}>
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
                                            orientation={"vertical"}
                                            className={cn(
                                                "flex touch-none select-none transition-colors",
                                                "w-1.5 bg-transparent",
                                            )}
                                        >
                                            <ScrollArea.Thumb
                                                className={
                                                    "relative flex-1 rounded-full bg-nb-gray-800 hover:bg-nb-gray-700"
                                                }
                                            />
                                        </ScrollArea.Scrollbar>
                                    </ScrollArea.Root>
                                    <div className={"-mx-1 h-px bg-nb-gray-910"} />
                                </>
                            )}

                            <div className={"pt-1"}>
                                <Command.Item
                                    value={MANAGE_VALUE}
                                    onSelect={handleManage}
                                    disabled={!onManageProfiles}
                                    className={cn(
                                        "flex items-center gap-2 px-2 py-1.5",
                                        "cursor-default rounded-md text-sm outline-none",
                                        "data-[selected=true]:bg-nb-gray-900",
                                        "data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50",
                                    )}
                                >
                                    <Settings2
                                        size={14}
                                        aria-hidden={"true"}
                                        className={"shrink-0"}
                                    />
                                    <span className={"flex-1 truncate"}>
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

// ForeignProfileNotice explains why no row in the list is marked active: the
// daemon is on a profile belonging to somebody else, which this user can
// neither read nor act on.
const ForeignProfileNotice = () => {
    const { t } = useTranslation();
    return (
        <div
            role={"note"}
            className={cn(
                "mb-1 flex items-start gap-2 rounded-md px-2 py-2",
                "bg-nb-gray-900/70 text-xs leading-snug text-nb-gray-300 dark:bg-nb-gray-900",
            )}
        >
            <Lock size={13} aria-hidden={"true"} className={"mt-0.5 shrink-0"} />
            {/* The popover sizes itself to its content, so without a cap the
                sentence would render on one line and widen the whole list. */}
            <span className={"max-w-[14rem]"}>{t("profile.ownedByAnother.hint")}</span>
        </div>
    );
};

const ProfileTriggerSkeleton = () => (
    <div
        role={"status"}
        aria-busy={"true"}
        aria-live={"polite"}
        className={"wails-no-draggable flex h-10 select-none items-center gap-2 rounded-lg px-3"}
    >
        <div
            aria-hidden={"true"}
            className={"size-4 shrink-0 animate-pulse rounded-full bg-nb-gray-900"}
        />
        <div aria-hidden={"true"} className={"h-4 w-24 animate-pulse rounded bg-nb-gray-900"} />
    </div>
);

type ProfileTriggerButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    name: string;
    // locked marks the active profile as one this user cannot act on. The name
    // is then wording of our own rather than a profile's, so it gets a neutral
    // icon instead of one picked from it.
    locked?: boolean;
};

const ProfileTriggerButton = forwardRef<HTMLButtonElement, ProfileTriggerButtonProps>(
    function ProfileTriggerButton({ name, locked, className, disabled, ...props }, ref) {
        const { t } = useTranslation();
        const isFocusVisible = useFocusVisible();
        const Icon = locked ? Lock : (pickProfileIcon(name) ?? UserCircle);
        return (
            <button
                ref={ref}
                type={"button"}
                disabled={disabled}
                tabIndex={disabled ? -1 : 0}
                aria-label={t("header.profile.switch")}
                aria-haspopup={"listbox"}
                className={cn(
                    "wails-no-draggable flex h-10 cursor-default select-none items-center gap-2 rounded-lg px-3 outline-none",
                    "text-nb-gray-200 hover:bg-nb-gray-800 dark:hover:bg-nb-gray-900",
                    "data-[state=open]:bg-nb-gray-800 dark:data-[state=open]:bg-nb-gray-900",
                    "disabled:opacity-50 disabled:hover:bg-transparent dark:disabled:hover:bg-transparent",
                    isFocusVisible &&
                        "focus-visible:ring-2 focus-visible:ring-nb-gray-50/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                    "wails-no-draggable transition-colors duration-150",
                    className,
                )}
                {...props}
            >
                <Icon
                    size={16}
                    aria-hidden={"true"}
                    className={"wails-no-draggable shrink-0 text-nb-gray-200"}
                />
                <span
                    className={cn(
                        "wails-no-draggable truncate text-sm font-medium",
                        // Wording of ours rather than a name, and the longest
                        // translation of it does not fit the name budget.
                        locked ? "max-w-[170px]" : "max-w-[140px]",
                    )}
                >
                    {name}
                </span>
                <ChevronDown
                    size={14}
                    aria-hidden={"true"}
                    className={"wails-no-draggable shrink-0 text-nb-gray-200"}
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
                "flex w-auto gap-2 px-2 py-2 pr-3 last:mb-1",
                "cursor-default rounded-md text-sm outline-none",
                "data-[selected=true]:bg-nb-gray-900",
                showEmail ? "items-start" : "items-center",
            )}
        >
            <div className={"flex min-w-0 flex-1 flex-col leading-tight"}>
                <span className={"truncate"}>{profile.name}</span>
                {showEmail && <TruncatedEmail email={profile.email} />}
            </div>
            {isActive && (
                <Check
                    size={16}
                    aria-hidden={"true"}
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
        <span ref={ref} className={"mt-0.5 max-w-[180px] truncate text-xs text-nb-gray-300"}>
            {email}
        </span>
    );
    if (!overflowing) return span;
    return <Tooltip content={email}>{span}</Tooltip>;
};
