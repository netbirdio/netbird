import { useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorDialog, warningDialog } from "@/lib/dialogs.ts";
import { CircleMinus, PlusCircle, Trash2, UserCircle } from "lucide-react";
import type { Profile } from "@bindings/services/models.js";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/buttons/Button";
import HelpText from "@/components/typography/HelpText";
import { ProfileCreationModal } from "@/modules/profiles/ProfileCreationModal";
import { pickProfileIcon } from "@/modules/profiles/ProfileAvatar";
import { Tooltip } from "@/components/Tooltip";
import i18next from "@/lib/i18n";
import { useProfile } from "@/contexts/ProfileContext";
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

    const [newOpen, setNewOpen] = useState(false);
    const [busy, setBusy] = useState(false);

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

    const handleDeregister = async (name: string) => {
        const cancelLabel = i18next.t("common.cancel");
        const confirmLabel = i18next.t("profile.deregister.confirm");
        const result = await warningDialog({
            Title: i18next.t("profile.deregister.title"),
            Message: i18next.t("profile.deregister.message", { name }),
            Buttons: [
                { Label: cancelLabel, IsCancel: true },
                { Label: confirmLabel, IsDefault: true },
            ],
        });
        if (result !== confirmLabel) return;
        void guarded(i18next.t("profile.error.deregisterTitle"), () => logoutProfile(name));
    };

    const handleDelete = async (name: string) => {
        if (name === DEFAULT_PROFILE) return;
        const cancelLabel = i18next.t("common.cancel");
        const confirmLabel = i18next.t("common.delete");
        const result = await warningDialog({
            Title: i18next.t("profile.delete.title"),
            Message: i18next.t("profile.delete.message", { name }),
            Buttons: [
                { Label: cancelLabel, IsCancel: true },
                { Label: confirmLabel, IsDefault: true },
            ],
        });
        if (result !== confirmLabel) return;
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
        <>
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
        </>
    );
}

type ProfileRowProps = {
    profile: Profile;
    isActive: boolean;
    onDeregister: () => void;
    onDelete: () => void;
};

const ProfileRow = ({ profile, isActive, onDeregister, onDelete }: ProfileRowProps) => {
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
                    canDeregister={!!profile.email}
                    canDelete={profile.name !== DEFAULT_PROFILE}
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
    canDeregister: boolean;
    canDelete: boolean;
    onDeregister: () => void;
    onDelete: () => void;
};

const RowActions = ({ canDeregister, canDelete, onDeregister, onDelete }: RowActionsProps) => {
    const { t } = useTranslation();
    return (
        <div className={"inline-flex items-center gap-1"}>
            <ActionIconButton
                label={t("profile.selector.deregister")}
                icon={CircleMinus}
                onClick={onDeregister}
                hidden={!canDeregister}
            />
            <ActionIconButton
                label={t("profile.selector.delete")}
                icon={Trash2}
                onClick={onDelete}
                variant={"danger"}
                hidden={!canDelete}
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
};

const ActionIconButton = ({
    label,
    icon: Icon,
    onClick,
    variant = "default",
    hidden = false,
}: ActionIconButtonProps) => {
    const button = (
        <button
            type={"button"}
            onClick={onClick}
            aria-label={label}
            aria-hidden={hidden || undefined}
            tabIndex={hidden ? -1 : undefined}
            className={cn(
                "h-9 w-9 inline-flex items-center justify-center rounded-md cursor-default outline-none",
                "transition-colors duration-150",
                variant === "danger"
                    ? "text-nb-gray-400 hover:text-red-500 hover:bg-red-500/10"
                    : "text-nb-gray-400 hover:text-nb-gray-100 hover:bg-nb-gray-900",
                hidden && "opacity-0 pointer-events-none",
            )}
        >
            <Icon size={16} />
        </button>
    );
    if (hidden) return button;
    return (
        <Tooltip content={label} side={"top"}>
            {button}
        </Tooltip>
    );
};
