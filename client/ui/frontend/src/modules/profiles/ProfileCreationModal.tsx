import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import * as Dialog from "@/components/dialog/Dialog";
import { Input } from "@/components/inputs/Input";
import { Button } from "@/components/buttons/Button";
import { DialogActions } from "@/components/dialog/DialogActions";
import { Label } from "@/components/typography/Label";
import { HelpText } from "@/components/typography/HelpText";
import { ManagementServerSwitch } from "@/components/ManagementServerSwitch";
import {
    CLOUD_MANAGEMENT_URL,
    ManagementMode,
    checkManagementUrlReachable,
    isValidManagementUrl,
    normalizeManagementUrl,
} from "@/hooks/useManagementUrl";
import { useRestrictions } from "@/contexts/RestrictionsContext.tsx";

export type ProfileFormInitial = {
    name: string;
    managementUrl: string;
};

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSubmit: (name: string, managementUrl: string) => void | Promise<void>;
    initial?: ProfileFormInitial;
};

const MAX_PROFILE_NAME_LEN = 128;

export const ProfileCreationModal = ({ open, onOpenChange, onSubmit, initial }: Props) => {
    const { t } = useTranslation();
    const { mdm } = useRestrictions();
    const managedManagementUrl = mdm.managementURL;
    const nameId = useId();
    const urlId = useId();
    const isEdit = !!initial;
    const initialModeFromUrl = (u: string): ManagementMode =>
        u && u !== CLOUD_MANAGEMENT_URL ? ManagementMode.SelfHosted : ManagementMode.Cloud;
    const initialSelfHostedUrl = (u: string): string => (u && u !== CLOUD_MANAGEMENT_URL ? u : "");

    const [name, setName] = useState(initial?.name ?? "");
    const [nameError, setNameError] = useState<string | null>(null);
    const nameRef = useRef<HTMLInputElement>(null);

    const [mode, setMode] = useState<ManagementMode>(
        initial ? initialModeFromUrl(initial.managementUrl) : ManagementMode.Cloud,
    );
    const [url, setUrl] = useState(initial ? initialSelfHostedUrl(initial.managementUrl) : "");
    const [urlError, setUrlError] = useState<string | null>(null);
    const [unreachable, setUnreachable] = useState(false);
    const [checking, setChecking] = useState(false);
    const urlRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (open) {
            setName(initial?.name ?? "");
            setMode(initial ? initialModeFromUrl(initial.managementUrl) : ManagementMode.Cloud);
            setUrl(initial ? initialSelfHostedUrl(initial.managementUrl) : "");
            setNameError(null);
            setUrlError(null);
            setUnreachable(false);
            setChecking(false);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open, initial?.name, initial?.managementUrl]);

    const initialModeRef = useRef<ManagementMode>(ManagementMode.Cloud);
    useEffect(() => {
        if (!open) return;
        initialModeRef.current = mode;
        const id = globalThis.setTimeout(() => {
            nameRef.current?.focus();
            nameRef.current?.select();
        }, 0);
        return () => globalThis.clearTimeout(id);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [open]);

    // When the user toggles to Self-hosted inside the dialog (not on initial
    // open), move focus to the URL input so they can start typing immediately.
    useEffect(() => {
        if (!open) return;
        if (mode === initialModeRef.current) return;
        if (mode !== ManagementMode.SelfHosted) return;
        urlRef.current?.focus();
    }, [open, mode]);

    useEffect(() => {
        setUrlError(null);
        setUnreachable(false);
    }, [url, mode]);

    const resolveTargetUrl = (): { url: string; needsReachCheck: boolean } | null => {
        if (managedManagementUrl) {
            return { url: managedManagementUrl, needsReachCheck: false };
        }
        if (mode === ManagementMode.Cloud) {
            return { url: CLOUD_MANAGEMENT_URL, needsReachCheck: false };
        }
        const trimmed = url.trim();
        if (!trimmed || !isValidManagementUrl(trimmed)) {
            setUrlError(t("settings.general.management.urlError"));
            urlRef.current?.focus();
            return null;
        }
        const target = normalizeManagementUrl(trimmed);

        const unchanged = target === initial?.managementUrl;
        return { url: target, needsReachCheck: !unchanged };
    };

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        if (checking) return;

        const sanitized = name.trim();
        if (sanitized.length === 0) {
            setNameError(t("profile.dialog.required"));
            nameRef.current?.focus();
            return;
        }

        const target = resolveTargetUrl();
        if (!target) return;

        if (target.needsReachCheck) {
            setChecking(true);
            const reachable = await checkManagementUrlReachable(target.url);
            setChecking(false);
            if (!reachable && !unreachable) {
                setUnreachable(true);
                return;
            }
        }

        await onSubmit(sanitized, target.url);
        onOpenChange(false);
    };

    const handleNameChange = (value: string) => {
        setName(value);
        if (nameError) setNameError(null);
    };

    const trimmedUrl = url.trim();
    const showUrlSyntaxError =
        mode === ManagementMode.SelfHosted &&
        trimmedUrl !== "" &&
        !isValidManagementUrl(trimmedUrl);
    const urlInputError = showUrlSyntaxError
        ? t("settings.general.management.urlError")
        : (urlError ?? undefined);
    const urlInputWarning =
        !urlInputError && unreachable ? t("profile.dialog.urlUnreachable") : undefined;

    return (
        <Dialog.Root open={open} onOpenChange={onOpenChange}>
            <Dialog.Content
                maxWidthClass={"max-w-md"}
                showClose={false}
                className={"py-7"}
                srTitle={isEdit ? t("profile.edit.title") : t("profile.dialog.title")}
                srDescription={t("profile.dialog.description")}
                onOpenAutoFocus={(e) => {
                    e.preventDefault();
                    // Focus + select-all so editing an existing name is one
                    // keystroke away from overwriting it.
                    nameRef.current?.focus();
                    nameRef.current?.select();
                }}
            >
                <form onSubmit={handleSubmit}>
                    <div className={"flex flex-col gap-6 px-7"}>
                        <div className={"flex flex-col gap-2"}>
                            <div className={"pl-1"}>
                                <Label htmlFor={nameId} className={"mb-0.5"}>
                                    {t("profile.dialog.nameLabel")}
                                </Label>
                                <HelpText margin={false}>
                                    {t("profile.dialog.description")}
                                </HelpText>
                            </div>
                            <Input
                                id={nameId}
                                ref={nameRef}
                                autoFocus
                                placeholder={t("profile.dialog.placeholder")}
                                value={name}
                                onChange={(e) => handleNameChange(e.target.value)}
                                error={nameError ?? undefined}
                                maxLength={MAX_PROFILE_NAME_LEN}
                                spellCheck={false}
                                autoComplete={"off"}
                                autoCapitalize={"off"}
                            />
                        </div>

                        {!managedManagementUrl && (
                            <div className={"flex flex-col gap-2"}>
                                <div className={"pl-1"}>
                                    <Label as={"div"} className={"mb-0.5"}>
                                        {t("settings.general.management.label")}
                                    </Label>
                                    <HelpText margin={false}>
                                        {t("profile.dialog.managementHelp")}
                                    </HelpText>
                                </div>
                                <div className={"flex flex-col gap-3"}>
                                    <ManagementServerSwitch
                                        value={mode}
                                        onChange={setMode}
                                        fullWidth
                                    />
                                    {mode === ManagementMode.SelfHosted && (
                                        <Input
                                            id={urlId}
                                            ref={urlRef}
                                            aria-label={t("settings.general.management.label")}
                                            placeholder={t(
                                                "settings.general.management.urlPlaceholder",
                                            )}
                                            value={url}
                                            onChange={(e) => setUrl(e.target.value)}
                                            error={urlInputError}
                                            warning={urlInputWarning}
                                            spellCheck={false}
                                            autoComplete={"off"}
                                            autoCorrect={"off"}
                                            autoCapitalize={"off"}
                                        />
                                    )}
                                </div>
                            </div>
                        )}

                        <DialogActions className={"flex-row items-center justify-end gap-2.5 pt-2"}>
                            <Button
                                type={"button"}
                                variant={"secondary"}
                                size={"sm"}
                                disabled={checking}
                                onClick={() => onOpenChange(false)}
                            >
                                {t("common.cancel")}
                            </Button>
                            <Button
                                type={"submit"}
                                variant={"primary"}
                                size={"sm"}
                                loading={checking}
                            >
                                {isEdit ? t("profile.edit.submit") : t("profile.dialog.submit")}
                            </Button>
                        </DialogActions>
                    </div>
                </form>
            </Dialog.Content>
        </Dialog.Root>
    );
};
