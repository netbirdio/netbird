import { type KeyboardEvent, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
    CircleMinus,
    LogIn,
    MoreVertical,
    PencilLine,
    PlusCircle,
    Trash2,
    UserCircle,
} from "lucide-react";
import type { Profile } from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import HelpText from "@/components/typography/HelpText";
import {
    ProfileCreationModal,
    type ProfileFormInitial,
} from "@/modules/profiles/ProfileCreationModal";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import { Tooltip } from "@/components/Tooltip";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/DropdownMenu";
import i18next from "@/lib/i18n";
import { useProfile } from "@/contexts/ProfileContext";
import { useConfirm } from "@/contexts/DialogContext";
import { Settings as SettingsSvc } from "@bindings/services";
import { SetConfigParams } from "@bindings/services/models.js";
import { isNetbirdCloud } from "@/hooks/useManagementUrl.ts";
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";
import { cn } from "@/lib/cn";
import { reconcileOrder } from "@/lib/sorting";
import { errorDialog, formatErrorMessage } from "@/lib/errors";

const DEFAULT_PROFILE_ID = "default";

export function ProfilesTab() {
    const { t } = useTranslation();
    const {
        profiles,
        activeProfileId,
        loaded,
        username,
        switchProfile,
        addProfile,
        removeProfile,
        renameProfile,
        logoutProfile,
    } = useProfile();

    const confirm = useConfirm();
    const [newOpen, setNewOpen] = useState(false);
    const [editTarget, setEditTarget] = useState<{
        profile: Profile;
        initial: ProfileFormInitial;
    } | null>(null);
    const [busy, setBusy] = useState(false);

    // Order is held stable so switching only flips the badge, never reorders rows
    // (else the clicked row jumps to the top under the cursor).
    const orderRef = useRef<string[]>([]);
    const ordered = useMemo(() => {
        const { order, items } = reconcileOrder(
            orderRef.current,
            profiles,
            (p) => p.id,
            (a, b) => {
                if (a.id === activeProfileId) return -1;
                if (b.id === activeProfileId) return 1;
                return a.name.localeCompare(b.name);
            },
        );
        orderRef.current = order;
        return items;
    }, [profiles, activeProfileId]);

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

    const handleSwitch = async (id: string, name: string) => {
        const ok = await confirm({
            title: t("profile.switch.title", { name }),
            description: t("profile.switch.message", { name }),
            confirmLabel: t("profile.switch.confirm"),
        });
        if (!ok) return;
        await guarded(i18next.t("profile.error.switchTitle"), () => switchProfile(id));
    };

    const handleDeregister = async (id: string, name: string) => {
        const ok = await confirm({
            title: t("profile.deregister.title", { name }),
            description: t("profile.deregister.message", { name }),
            confirmLabel: t("profile.deregister.confirm"),
        });
        if (!ok) return;
        void guarded(i18next.t("profile.error.deregisterTitle"), () => logoutProfile(id));
    };

    const handleDelete = async (id: string, name: string) => {
        if (id === DEFAULT_PROFILE_ID) return;
        const ok = await confirm({
            title: t("profile.delete.title", { name }),
            description: t("profile.delete.message", { name }),
            confirmLabel: t("common.delete"),
            danger: true,
        });
        if (!ok) return;
        void guarded(i18next.t("profile.error.deleteTitle"), () => removeProfile(id));
    };

    const handleCreate = async (name: string, managementUrl: string) => {
        await guarded(i18next.t("profile.error.createTitle"), async () => {
            const id = await addProfile(name);
            // SetConfig is keyed by the new profile's ID, so it writes the
            // not-yet-active profile. Write before switching so any reconnect
            // targets the right deployment.
            if (!isNetbirdCloud(managementUrl)) {
                await SettingsSvc.SetConfig(
                    new SetConfigParams({ profileName: id, username, managementUrl }),
                );
            }
            await switchProfile(id);
        });
    };

    const handleEdit = async (id: string, name: string) => {
        await guarded(i18next.t("profile.error.editTitle"), async () => {
            const config = await SettingsSvc.GetConfig({ profileName: id, username });
            const profile = profiles.find((p) => p.id === id);
            if (!profile) return;
            setEditTarget({
                profile,
                initial: { name, managementUrl: config.managementUrl },
            });
        });
    };

    const handleSave = async (name: string, managementUrl: string) => {
        if (!editTarget) return;
        const { profile, initial } = editTarget;
        await guarded(i18next.t("profile.error.editTitle"), async () => {
            if (name !== initial.name) {
                await renameProfile(profile.id, name);
            }
            if (managementUrl !== initial.managementUrl) {
                await SettingsSvc.SetConfig(
                    new SetConfigParams({
                        profileName: profile.id,
                        username,
                        managementUrl,
                    }),
                );
            }
        });
    };

    return (
        <div>
            <SectionGroup title={t("settings.profiles.section.profiles")}>
                <HelpText className={"-mt-2 mb-0"}>{t("settings.profiles.intro")}</HelpText>

                <div
                    className={cn(
                        "overflow-hidden rounded-xl border border-nb-gray-900 bg-nb-gray-930/60",
                    )}
                >
                    <ProfilesTable
                        ordered={ordered}
                        activeProfileId={activeProfileId}
                        onSwitch={handleSwitch}
                        onEdit={handleEdit}
                        onDeregister={handleDeregister}
                        onDelete={handleDelete}
                    />

                    {loaded && ordered.length === 0 && (
                        <div
                            className={
                                "flex flex-col items-center justify-center py-10 text-center"
                            }
                        >
                            <UserCircle
                                size={28}
                                aria-hidden={"true"}
                                className={"mb-2 text-nb-gray-500"}
                            />
                            <p className={"text-sm font-semibold text-nb-gray-200"}>
                                {t("settings.profiles.emptyTitle")}
                            </p>
                            <p className={"mt-1 max-w-sm text-balance text-xs text-nb-gray-400"}>
                                {t("settings.profiles.emptyDescription")}
                            </p>
                        </div>
                    )}
                </div>

                <SettingsBottomBar>
                    <Button variant={"primary"} size={"md"} onClick={() => setNewOpen(true)}>
                        <PlusCircle size={14} aria-hidden={"true"} />
                        {t("settings.profiles.addProfile")}
                    </Button>
                </SettingsBottomBar>
            </SectionGroup>

            <ProfileCreationModal
                open={newOpen}
                onOpenChange={setNewOpen}
                onSubmit={handleCreate}
            />

            <ProfileCreationModal
                open={editTarget !== null}
                onOpenChange={(o) => {
                    if (!o) setEditTarget(null);
                }}
                initial={editTarget?.initial}
                onSubmit={handleSave}
            />
        </div>
    );
}

type ProfilesTableProps = {
    ordered: Profile[];
    activeProfileId: string | undefined;
    onSwitch: (id: string, name: string) => void;
    onEdit: (id: string, name: string) => void;
    onDeregister: (id: string, name: string) => void;
    onDelete: (id: string, name: string) => void;
};

const ProfilesTable = ({
    ordered,
    activeProfileId,
    onSwitch,
    onEdit,
    onDeregister,
    onDelete,
}: ProfilesTableProps) => {
    const { t } = useTranslation();
    const [focusedIndex, setFocusedIndex] = useState(0);
    const rowRefs = useRef<Map<string, HTMLTableRowElement>>(new Map());

    const focusRow = (index: number) => {
        if (index < 0 || index >= ordered.length) return;
        setFocusedIndex(index);
        const el = rowRefs.current.get(ordered[index].id);
        el?.focus();
    };

    const actionButtonsIn = (row: HTMLTableRowElement | undefined) =>
        Array.from(
            row?.querySelectorAll<HTMLButtonElement>(
                "button:not([aria-hidden='true']):not([aria-disabled='true'])",
            ) ?? [],
        );

    const handleRowKey = (e: KeyboardEvent<HTMLTableRowElement>, index: number): boolean => {
        switch (e.key) {
            case "ArrowDown":
                focusRow(Math.min(index + 1, ordered.length - 1));
                return true;
            case "ArrowUp":
                focusRow(Math.max(index - 1, 0));
                return true;
            case "Home":
                focusRow(0);
                return true;
            case "End":
                focusRow(ordered.length - 1);
                return true;
        }
        return false;
    };

    const handleButtonKey = (
        e: KeyboardEvent<HTMLTableRowElement>,
        index: number,
        row: HTMLTableRowElement,
    ): boolean => {
        const buttons = actionButtonsIn(row);
        const current = buttons.indexOf(e.target as HTMLButtonElement);
        if (current === -1) return false;

        switch (e.key) {
            case "ArrowDown":
                focusRow(Math.min(index + 1, ordered.length - 1));
                return true;
            case "ArrowUp":
                focusRow(Math.max(index - 1, 0));
                return true;
            case "Escape":
                row.focus();
                return true;
            case "Tab":
                // At the last button: jump to the next row instead of exiting the table.
                // At the first button with Shift+Tab: jump back to the row.
                if (!e.shiftKey && current === buttons.length - 1 && index < ordered.length - 1) {
                    focusRow(index + 1);
                    return true;
                }
                if (e.shiftKey && current === 0) {
                    row.focus();
                    return true;
                }
                return false;
        }
        return false;
    };

    const handleRowKeyDown = (e: KeyboardEvent<HTMLTableRowElement>, index: number) => {
        const row = rowRefs.current.get(ordered[index].id);
        if (!row) return;
        const onRow = e.target === row;
        const handled = onRow ? handleRowKey(e, index) : handleButtonKey(e, index, row);
        if (handled) e.preventDefault();
    };

    const safeFocusedIndex = Math.min(focusedIndex, Math.max(0, ordered.length - 1));

    return (
        <table
            aria-label={t("settings.profiles.section.profiles")}
            className={"w-full border-separate border-spacing-0 text-sm"}
        >
            <tbody className={"flex flex-col"}>
                {ordered.map((profile, index) => (
                    <ProfileRow
                        key={profile.id}
                        profile={profile}
                        isActive={profile.id === activeProfileId}
                        isFocused={index === safeFocusedIndex}
                        isFirst={index === 0}
                        isLast={index === ordered.length - 1}
                        rowRef={(el) => {
                            if (el) rowRefs.current.set(profile.id, el);
                            else rowRefs.current.delete(profile.id);
                        }}
                        onKeyDown={(e) => handleRowKeyDown(e, index)}
                        onFocus={() => setFocusedIndex(index)}
                        onSwitch={() => onSwitch(profile.id, profile.name)}
                        onEdit={() => onEdit(profile.id, profile.name)}
                        onDeregister={() => onDeregister(profile.id, profile.name)}
                        onDelete={() => onDelete(profile.id, profile.name)}
                    />
                ))}
            </tbody>
        </table>
    );
};

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    isFocused: boolean;
    isFirst: boolean;
    isLast: boolean;
    rowRef: (el: HTMLTableRowElement | null) => void;
    onKeyDown: (e: KeyboardEvent<HTMLTableRowElement>) => void;
    onFocus: () => void;
    onSwitch: () => void;
    onEdit: () => void;
    onDeregister: () => void;
    onDelete: () => void;
};

const ProfileRow = ({
    profile,
    isActive,
    isFocused,
    isFirst,
    isLast,
    rowRef,
    onKeyDown,
    onFocus,
    onSwitch,
    onEdit,
    onDeregister,
    onDelete,
}: ProfileRowProps) => {
    const { t } = useTranslation();
    const Icon = pickProfileIcon(profile.name) ?? UserCircle;
    const showEmail = !!profile.email;

    return (
        <tr
            ref={rowRef}
            tabIndex={isFocused ? 0 : -1}
            onKeyDown={onKeyDown}
            onFocus={onFocus}
            aria-label={profile.name}
            className={cn(
                "flex items-center gap-4 px-4 py-2.5",
                "border-b border-nb-gray-910 last:border-b-0",
                "outline-none",
                isFirst && "rounded-t-xl",
                isLast && "rounded-b-xl",
                "focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-white/60",
            )}
        >
            <td
                className={cn(
                    "flex min-w-0 flex-1 gap-2 leading-tight",
                    showEmail ? "items-start" : "items-center",
                )}
            >
                <Icon
                    size={15}
                    aria-hidden={"true"}
                    className={cn("shrink-0 text-nb-gray-200", showEmail ? "mt-0.5" : "")}
                />
                <div className={"flex min-w-0 flex-1 flex-col leading-tight"}>
                    <div className={"flex min-w-0 items-center gap-2"}>
                        <span
                            className={
                                "cursor-text select-text truncate font-medium text-nb-gray-100"
                            }
                        >
                            {profile.name}
                        </span>
                        {isActive && <Badge>{t("settings.profiles.active")}</Badge>}
                    </div>
                    {showEmail && <TruncatedEmail email={profile.email} />}
                </div>
            </td>
            <td className={"shrink-0 text-right"}>
                <RowActions
                    canSwitch={!isActive}
                    canDeregister={!!profile.email}
                    isDefault={profile.id === DEFAULT_PROFILE_ID}
                    isActive={isActive}
                    rowFocused={isFocused}
                    onSwitch={onSwitch}
                    onEdit={onEdit}
                    onDeregister={onDeregister}
                    onDelete={onDelete}
                />
            </td>
        </tr>
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
        <span
            ref={ref}
            className={"mt-0.5 cursor-text select-text truncate text-xs text-nb-gray-300"}
        >
            {email}
        </span>
    );
    if (!overflowing) return span;
    return <Tooltip content={email}>{span}</Tooltip>;
};

type RowActionsProps = {
    canSwitch: boolean;
    canDeregister: boolean;
    isDefault: boolean;
    isActive: boolean;
    rowFocused: boolean;
    onSwitch: () => void;
    onEdit: () => void;
    onDeregister: () => void;
    onDelete: () => void;
};

const RowActions = ({
    canSwitch,
    canDeregister,
    isDefault,
    isActive,
    rowFocused,
    onSwitch,
    onEdit,
    onDeregister,
    onDelete,
}: RowActionsProps) => {
    const { t } = useTranslation();
    const deleteDisabled = isDefault || isActive;
    let deleteDisabledReason: string | null = null;
    if (isDefault) deleteDisabledReason = t("profile.delete.disabledDefault");
    else if (isActive) deleteDisabledReason = t("profile.delete.disabledActive");
    return (
        <div className={"inline-flex items-center gap-1"}>
            <ActionIconButton
                label={t("profile.selector.switchTo")}
                icon={LogIn}
                onClick={onSwitch}
                hidden={!canSwitch}
                tabbable={rowFocused}
            />
            <RowMoreMenu
                canDeregister={canDeregister}
                deleteDisabled={deleteDisabled}
                deleteDisabledReason={deleteDisabledReason}
                rowFocused={rowFocused}
                onEdit={onEdit}
                onDeregister={onDeregister}
                onDelete={onDelete}
            />
        </div>
    );
};

type RowMoreMenuProps = {
    canDeregister: boolean;
    deleteDisabled: boolean;
    deleteDisabledReason: string | null;
    rowFocused: boolean;
    onEdit: () => void;
    onDeregister: () => void;
    onDelete: () => void;
};

const RowMoreMenu = ({
    canDeregister,
    deleteDisabled,
    deleteDisabledReason,
    rowFocused,
    onEdit,
    onDeregister,
    onDelete,
}: RowMoreMenuProps) => {
    const { t } = useTranslation();
    const moreLabel = t("profile.selector.moreOptions");
    return (
        <DropdownMenu modal={false}>
            <DropdownMenuTrigger asChild>
                <button
                    type={"button"}
                    aria-label={moreLabel}
                    tabIndex={rowFocused ? 0 : -1}
                    className={cn(
                        "inline-flex h-9 w-9 cursor-default items-center justify-center rounded-md outline-none",
                        "text-nb-gray-400 hover:bg-nb-gray-900 hover:text-nb-gray-100",
                        "transition-colors duration-150",
                        "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                        "data-[state=open]:bg-nb-gray-900 data-[state=open]:text-nb-gray-100",
                    )}
                >
                    <MoreVertical size={16} aria-hidden={"true"} />
                </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align={"end"} sideOffset={4} className={"min-w-36 select-none"}>
                <DropdownMenuItem onClick={onEdit}>
                    <div className={"flex w-full items-center gap-2"}>
                        <PencilLine size={14} aria-hidden={"true"} />
                        <span className={"flex-1"}>{t("profile.selector.edit")}</span>
                    </div>
                </DropdownMenuItem>
                {canDeregister && (
                    <DropdownMenuItem onClick={onDeregister}>
                        <div className={"flex w-full items-center gap-2"}>
                            <CircleMinus size={14} aria-hidden={"true"} />
                            <span className={"flex-1"}>{t("profile.selector.deregister")}</span>
                        </div>
                    </DropdownMenuItem>
                )}
                <DeleteMenuItem
                    disabled={deleteDisabled}
                    disabledReason={deleteDisabledReason}
                    onDelete={onDelete}
                />
            </DropdownMenuContent>
        </DropdownMenu>
    );
};

type DeleteMenuItemProps = {
    disabled: boolean;
    disabledReason: string | null;
    onDelete: () => void;
};

const DeleteMenuItem = ({ disabled, disabledReason, onDelete }: DeleteMenuItemProps) => {
    const { t } = useTranslation();
    const item = (
        <DropdownMenuItem
            disabled={disabled}
            onClick={disabled ? undefined : onDelete}
            className={cn(!disabled && "text-red-500 hover:!text-red-500 focus:text-red-500")}
        >
            <div className={"flex w-full items-center gap-2"}>
                <Trash2 size={14} aria-hidden={"true"} />
                <span className={"flex-1"}>{t("profile.selector.delete")}</span>
            </div>
        </DropdownMenuItem>
    );
    if (!disabled || !disabledReason) return item;
    return (
        <Tooltip
            content={<span className={"block max-w-[260px] leading-snug"}>{disabledReason}</span>}
            side={"left"}
        >
            <span className={"block"}>{item}</span>
        </Tooltip>
    );
};

type ActionIconButtonProps = {
    label: string;
    icon: typeof CircleMinus;
    onClick: () => void;
    variant?: "default" | "danger";
    /** Occupies space but invisible and non-interactive (preserves row layout). */
    hidden?: boolean;
    disabled?: boolean;
    tabbable?: boolean;
};

const ActionIconButton = ({
    label,
    icon: Icon,
    onClick,
    variant = "default",
    hidden = false,
    disabled = false,
    tabbable = true,
}: ActionIconButtonProps) => {
    const button = (
        <button
            type={"button"}
            onClick={disabled ? undefined : onClick}
            aria-label={label}
            aria-hidden={hidden || undefined}
            aria-disabled={disabled || undefined}
            tabIndex={hidden || !tabbable ? -1 : 0}
            className={cn(
                "inline-flex h-9 w-9 cursor-default items-center justify-center rounded-md outline-none",
                "transition-colors duration-150",
                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                variant === "danger"
                    ? "text-nb-gray-400 hover:bg-red-500/10 hover:text-red-500"
                    : "text-nb-gray-400 hover:bg-nb-gray-900 hover:text-nb-gray-100",
                hidden && "pointer-events-none opacity-0",
                disabled &&
                    "cursor-not-allowed opacity-40 hover:!bg-transparent hover:!text-nb-gray-400",
            )}
        >
            <Icon size={16} aria-hidden={"true"} />
        </button>
    );
    if (hidden) return button;
    return (
        <Tooltip
            content={<span className={"block max-w-[260px] leading-snug"}>{label}</span>}
            side={"top"}
        >
            {button}
        </Tooltip>
    );
};
