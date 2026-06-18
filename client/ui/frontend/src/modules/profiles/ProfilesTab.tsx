import { KeyboardEvent, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { CircleMinus, LogIn, PlusCircle, Trash2, UserCircle } from "lucide-react";
import type { Profile } from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import HelpText from "@/components/typography/HelpText";
import { ProfileCreationModal } from "@/modules/profiles/ProfileCreationModal";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import { Tooltip } from "@/components/Tooltip";
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

const DEFAULT_PROFILE = "default";

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
        logoutProfile,
    } = useProfile();

    const confirm = useConfirm();
    const [newOpen, setNewOpen] = useState(false);
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
        if (name === DEFAULT_PROFILE) return;
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

    return (
        <div>
            <SectionGroup title={t("settings.profiles.section.profiles")}>
                <HelpText className={"-mt-2 mb-0"}>{t("settings.profiles.intro")}</HelpText>

                <div
                    className={cn(
                        "bg-nb-gray-930/60 border border-nb-gray-900 rounded-xl overflow-hidden",
                    )}
                >
                    <ProfilesTable
                        ordered={ordered}
                        activeProfileId={activeProfileId}
                        onSwitch={handleSwitch}
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
                                aria-hidden="true"
                                className={"text-nb-gray-500 mb-2"}
                            />
                            <p className={"text-sm font-semibold text-nb-gray-200"}>
                                {t("settings.profiles.emptyTitle")}
                            </p>
                            <p className={"mt-1 text-xs text-nb-gray-400 max-w-sm text-balance"}>
                                {t("settings.profiles.emptyDescription")}
                            </p>
                        </div>
                    )}
                </div>

                <SettingsBottomBar>
                    <Button variant={"primary"} size={"md"} onClick={() => setNewOpen(true)}>
                        <PlusCircle size={14} aria-hidden="true" />
                        {t("settings.profiles.addProfile")}
                    </Button>
                </SettingsBottomBar>
            </SectionGroup>

            <ProfileCreationModal
                open={newOpen}
                onOpenChange={setNewOpen}
                onCreate={handleCreate}
            />
        </div>
    );
}

type ProfilesTableProps = {
    ordered: Profile[];
    activeProfileId: string | undefined;
    onSwitch: (id: string, name: string) => void;
    onDeregister: (id: string, name: string) => void;
    onDelete: (id: string, name: string) => void;
};

const ProfilesTable = ({
    ordered,
    activeProfileId,
    onSwitch,
    onDeregister,
    onDelete,
}: ProfilesTableProps) => {
    const { t } = useTranslation();
    const [focusedIndex, setFocusedIndex] = useState(0);
    const rowRefs = useRef<Map<string, HTMLLIElement>>(new Map());

    const focusRow = (index: number) => {
        if (index < 0 || index >= ordered.length) return;
        setFocusedIndex(index);
        const el = rowRefs.current.get(ordered[index].id);
        el?.focus();
    };

    const handleRowKeyDown = (e: KeyboardEvent<HTMLLIElement>, index: number) => {
        switch (e.key) {
            case "ArrowDown":
                e.preventDefault();
                focusRow(Math.min(index + 1, ordered.length - 1));
                break;
            case "ArrowUp":
                e.preventDefault();
                focusRow(Math.max(index - 1, 0));
                break;
            case "Home":
                e.preventDefault();
                focusRow(0);
                break;
            case "End":
                e.preventDefault();
                focusRow(ordered.length - 1);
                break;
        }
    };

    const safeFocusedIndex = Math.min(focusedIndex, Math.max(0, ordered.length - 1));

    return (
        <ul
            role={"list"}
            className={"w-full text-sm flex flex-col"}
            aria-label={t("settings.profiles.section.profiles")}
        >
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
                    onDeregister={() => onDeregister(profile.id, profile.name)}
                    onDelete={() => onDelete(profile.id, profile.name)}
                />
            ))}
        </ul>
    );
};

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    isFocused: boolean;
    isFirst: boolean;
    isLast: boolean;
    rowRef: (el: HTMLLIElement | null) => void;
    onKeyDown: (e: KeyboardEvent<HTMLLIElement>) => void;
    onFocus: () => void;
    onSwitch: () => void;
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
    onDeregister,
    onDelete,
}: ProfileRowProps) => {
    const { t } = useTranslation();
    const Icon = pickProfileIcon(profile.name) ?? UserCircle;
    const showEmail = !!profile.email;

    return (
        <li
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
            <div
                className={cn(
                    "flex gap-2 min-w-0 leading-tight flex-1",
                    showEmail ? "items-start" : "items-center",
                )}
            >
                <Icon
                    size={15}
                    aria-hidden="true"
                    className={cn("text-nb-gray-200 shrink-0", showEmail ? "mt-0.5" : "")}
                />
                <div className={"flex flex-col min-w-0 flex-1 leading-tight"}>
                    <div className={"flex items-center gap-2 min-w-0"}>
                        <span
                            className={
                                "truncate font-medium text-nb-gray-100 select-text cursor-text"
                            }
                        >
                            {profile.name}
                        </span>
                        {isActive && <Badge>{t("settings.profiles.active")}</Badge>}
                    </div>
                    {showEmail && <TruncatedEmail email={profile.email} />}
                </div>
            </div>
            <div className={"shrink-0 text-right"}>
                <RowActions
                    canSwitch={!isActive}
                    canDeregister={!!profile.email}
                    isDefault={profile.name === DEFAULT_PROFILE}
                    isActive={isActive}
                    rowFocused={isFocused}
                    onSwitch={onSwitch}
                    onDeregister={onDeregister}
                    onDelete={onDelete}
                />
            </div>
        </li>
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
            className={"text-xs text-nb-gray-300 truncate mt-0.5 select-text cursor-text"}
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
    onDeregister,
    onDelete,
}: RowActionsProps) => {
    const { t } = useTranslation();
    const deleteDisabled = isDefault || isActive;
    const nonDefaultDeleteLabel = isActive
        ? t("profile.delete.disabledActive")
        : t("profile.selector.delete");
    const deleteLabel = isDefault ? t("profile.delete.disabledDefault") : nonDefaultDeleteLabel;
    return (
        <div className={"inline-flex items-center gap-1"}>
            <ActionIconButton
                label={t("profile.selector.deregister")}
                icon={CircleMinus}
                onClick={onDeregister}
                hidden={!canDeregister}
                tabbable={rowFocused}
            />
            <ActionIconButton
                label={deleteLabel}
                icon={Trash2}
                onClick={onDelete}
                variant={"danger"}
                disabled={deleteDisabled}
                tabbable={rowFocused}
            />
            <ActionIconButton
                label={t("profile.selector.switchTo")}
                icon={LogIn}
                onClick={onSwitch}
                hidden={!canSwitch}
                tabbable={rowFocused}
            />
        </div>
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
                "h-9 w-9 inline-flex items-center justify-center rounded-md cursor-default outline-none",
                "transition-colors duration-150",
                "focus-visible:ring-2 focus-visible:ring-white/60 focus-visible:ring-offset-2 focus-visible:ring-offset-nb-gray-940",
                variant === "danger"
                    ? "text-nb-gray-400 hover:text-red-500 hover:bg-red-500/10"
                    : "text-nb-gray-400 hover:text-nb-gray-100 hover:bg-nb-gray-900",
                hidden && "opacity-0 pointer-events-none",
                disabled &&
                    "opacity-40 cursor-not-allowed hover:!text-nb-gray-400 hover:!bg-transparent",
            )}
        >
            <Icon size={16} aria-hidden="true" />
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
