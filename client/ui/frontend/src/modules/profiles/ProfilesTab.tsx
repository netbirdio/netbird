import { useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDialog } from "@/lib/dialogs.ts";
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
import { SectionGroup, SettingsBottomBar } from "@/modules/settings/SettingsSection.tsx";
import { cn } from "@/lib/cn";
import { formatErrorMessage } from "@/lib/errors";

const DEFAULT_PROFILE = "default";

export function ProfilesTab() {
    const { t } = useTranslation();
    const {
        profiles,
        activeProfile,
        loaded,
        switchProfile,
        addProfile,
        removeProfile,
        logoutProfile,
    } = useProfile();

    const confirm = useConfirm();
    const [newOpen, setNewOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const tabRootRef = useRef<HTMLDivElement>(null);

    // After a successful switch we want to bring the user back to the top of
    // the tab — the table re-sorts the new active profile to the row 0 and a
    // user who scrolled to find a target down the list would otherwise lose
    // visual anchoring. Settings is hosted inside a Radix ScrollArea so we
    // walk up to the viewport (it owns the actual overflow) instead of
    // `window.scrollTo`, which is a no-op here.
    const scrollTabToTop = () => {
        const el = tabRootRef.current?.closest<HTMLElement>(
            "[data-radix-scroll-area-viewport]",
        );
        el?.scrollTo({ top: 0, behavior: "smooth" });
    };

    const sorted = [...profiles].sort((a, b) => {
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
            await errorDialog({
                Title: title,
                Message: formatErrorMessage(e),
            });
        } finally {
            setBusy(false);
        }
    };

    const handleSwitch = async (name: string) => {
        const ok = await confirm({
            title: t("profile.switch.title", { name }),
            description: t("profile.switch.message", { name }),
            confirmLabel: t("profile.switch.confirm"),
        });
        if (!ok) return;
        await guarded(i18next.t("profile.error.switchTitle"), () => switchProfile(name));
        scrollTabToTop();
    };

    const handleDeregister = async (name: string) => {
        const ok = await confirm({
            title: t("profile.deregister.title", { name }),
            description: t("profile.deregister.message", { name }),
            confirmLabel: t("profile.deregister.confirm"),
        });
        if (!ok) return;
        void guarded(i18next.t("profile.error.deregisterTitle"), () => logoutProfile(name));
    };

    const handleDelete = async (name: string) => {
        if (name === DEFAULT_PROFILE) return;
        const ok = await confirm({
            title: t("profile.delete.title", { name }),
            description: t("profile.delete.message", { name }),
            confirmLabel: t("common.delete"),
            danger: true,
        });
        if (!ok) return;
        void guarded(i18next.t("profile.error.deleteTitle"), () => removeProfile(name));
    };

    const handleCreate = async (name: string) => {
        try {
            await addProfile(name);
            await switchProfile(name);
        } catch (e) {
            await errorDialog({
                Title: i18next.t("profile.error.createTitle"),
                Message: formatErrorMessage(e),
            });
        }
    };

    return (
        <div ref={tabRootRef}>
            <SectionGroup title={t("settings.profiles.section.profiles")}>
                <HelpText className={"-mt-2 mb-0"}>{t("settings.profiles.intro")}</HelpText>

                <div
                    className={cn(
                        "bg-nb-gray-930/60 border border-nb-gray-900 rounded-xl overflow-hidden",
                    )}
                >
                    <table className={"w-full text-sm"}>
                        <tbody>
                            {sorted.map((profile) => (
                                <ProfileRow
                                    key={profile.name}
                                    profile={profile}
                                    isActive={profile.name === activeProfile}
                                    onSwitch={() => handleSwitch(profile.name)}
                                    onDeregister={() => handleDeregister(profile.name)}
                                    onDelete={() => handleDelete(profile.name)}
                                />
                            ))}
                        </tbody>
                    </table>

                    {loaded && sorted.length === 0 && (
                        <div
                            className={
                                "flex flex-col items-center justify-center py-10 text-center"
                            }
                        >
                            <UserCircle size={28} className={"text-nb-gray-500 mb-2"} />
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
                        <PlusCircle size={14} />
                        {t("settings.profiles.addProfile")}
                    </Button>
                </SettingsBottomBar>
            </SectionGroup>

            <ProfileCreationModal open={newOpen} onOpenChange={setNewOpen} onCreate={handleCreate} />
        </div>
    );
}

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    onSwitch: () => void;
    onDeregister: () => void;
    onDelete: () => void;
};

const ProfileRow = ({ profile, isActive, onSwitch, onDeregister, onDelete }: ProfileRowProps) => {
    const { t } = useTranslation();
    const Icon = pickProfileIcon(profile.name) ?? UserCircle;
    const showEmail = !!profile.email;

    return (
        <tr className={"border-b border-nb-gray-910 last:border-b-0"}>
            <td className={"px-4 py-2.5 align-middle"}>
                <div
                    className={cn(
                        "flex gap-2 min-w-0 leading-tight",
                        showEmail ? "items-start" : "items-center",
                    )}
                >
                    <Icon
                        size={15}
                        className={cn(
                            "text-nb-gray-200 shrink-0",

                            showEmail ? "mt-0.5" : "",
                        )}
                    />
                    <div className={"flex flex-col min-w-0 flex-1 leading-tight"}>
                        <div className={"flex items-center gap-2 min-w-0"}>
                            <span className={"truncate font-medium text-nb-gray-100 select-text cursor-text"}>
                                {profile.name}
                            </span>
                            {isActive && <Badge>{t("settings.profiles.active")}</Badge>}
                        </div>
                        {showEmail && <TruncatedEmail email={profile.email!} />}
                    </div>
                </div>
            </td>
            <td className={"px-4 py-2.5 text-right align-middle"}>
                <RowActions
                    canSwitch={!isActive}
                    canDeregister={!!profile.email}
                    isDefault={profile.name === DEFAULT_PROFILE}
                    isActive={isActive}
                    onSwitch={onSwitch}
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
        <span ref={ref} className={"text-xs text-nb-gray-300 truncate mt-0.5 select-text cursor-text"}>
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
    onSwitch: () => void;
    onDeregister: () => void;
    onDelete: () => void;
};

const RowActions = ({
    canSwitch,
    canDeregister,
    isDefault,
    isActive,
    onSwitch,
    onDeregister,
    onDelete,
}: RowActionsProps) => {
    const { t } = useTranslation();
    const deleteDisabled = isDefault || isActive;
    const deleteLabel = isDefault
        ? t("profile.delete.disabledDefault")
        : isActive
          ? t("profile.delete.disabledActive")
          : t("profile.selector.delete");
    return (
        <div className={"inline-flex items-center gap-1"}>
            <ActionIconButton
                label={t("profile.selector.deregister")}
                icon={CircleMinus}
                onClick={onDeregister}
                hidden={!canDeregister}
            />
            <ActionIconButton
                label={deleteLabel}
                icon={Trash2}
                onClick={onDelete}
                variant={"danger"}
                disabled={deleteDisabled}
            />
            <ActionIconButton
                label={t("profile.selector.switchTo")}
                icon={LogIn}
                onClick={onSwitch}
                hidden={!canSwitch}
            />
        </div>
    );
};

type ActionIconButtonProps = {
    label: string;
    icon: typeof CircleMinus;
    onClick: () => void;
    variant?: "default" | "danger";
    /** When true the button still occupies space (preserves row layout)
     *  but is invisible and non-interactive. */
    hidden?: boolean;
    /** When true the button is visible but non-interactive (greyed out). */
    disabled?: boolean;
};

const ActionIconButton = ({
    label,
    icon: Icon,
    onClick,
    variant = "default",
    hidden = false,
    disabled = false,
}: ActionIconButtonProps) => {
    const button = (
        <button
            type={"button"}
            onClick={disabled ? undefined : onClick}
            aria-label={label}
            aria-hidden={hidden || undefined}
            aria-disabled={disabled || undefined}
            tabIndex={hidden ? -1 : undefined}
            className={cn(
                "h-9 w-9 inline-flex items-center justify-center rounded-md cursor-default outline-none",
                "transition-colors duration-150",
                variant === "danger"
                    ? "text-nb-gray-400 hover:text-red-500 hover:bg-red-500/10"
                    : "text-nb-gray-400 hover:text-nb-gray-100 hover:bg-nb-gray-900",
                hidden && "opacity-0 pointer-events-none",
                disabled && "opacity-40 cursor-not-allowed hover:!text-nb-gray-400 hover:!bg-transparent",
            )}
        >
            <Icon size={16} />
        </button>
    );
    if (hidden) return button;
    return (
        <Tooltip
            content={
                <span className={"block max-w-[260px] leading-snug"}>{label}</span>
            }
            side={"top"}
        >
            {button}
        </Tooltip>
    );
};
