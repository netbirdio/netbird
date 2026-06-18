import { FormEvent, useEffect, useRef, useState } from "react";
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

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onCreate: (name: string, managementUrl: string) => void;
};

// The daemon (profilemanager.sanitizeDisplayName) accepts free-form display
// names — spaces, emoji, punctuation, any valid UTF-8 — stripping only control
// characters and capping the length. Since #6367 the on-disk ID is separate
// from the display name, so the raw input no longer needs to be coerced into a
// filename-safe slug client-side; just trim and let the daemon canonicalize.
const MAX_PROFILE_NAME_LEN = 128;

export const ProfileCreationModal = ({ open, onOpenChange, onCreate }: Props) => {
    const { t } = useTranslation();
    const { mdm } = useRestrictions();
    const managedManagementUrl = mdm.managementURL;
    const [name, setName] = useState("");
    const [nameError, setNameError] = useState<string | null>(null);
    const nameRef = useRef<HTMLInputElement>(null);

    const [mode, setMode] = useState<ManagementMode>(ManagementMode.Cloud);
    const [url, setUrl] = useState("");
    const [urlError, setUrlError] = useState<string | null>(null);
    const [unreachable, setUnreachable] = useState(false);
    const [checking, setChecking] = useState(false);
    const urlRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (!open) {
            setName("");
            setNameError(null);
            setMode(ManagementMode.Cloud);
            setUrl("");
            setUrlError(null);
            setUnreachable(false);
            setChecking(false);
        }
    }, [open]);

    useEffect(() => {
        setUrlError(null);
        setUnreachable(false);
    }, [url, mode]);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        if (checking) return;

        const sanitized = name.trim();
        if (sanitized.length === 0) {
            setNameError(t("profile.dialog.required"));
            nameRef.current?.focus();
            return;
        }

        if (managedManagementUrl) {
            onCreate(sanitized, managedManagementUrl);
            onOpenChange(false);
            return;
        }

        if (mode === ManagementMode.Cloud) {
            onCreate(sanitized, CLOUD_MANAGEMENT_URL);
            onOpenChange(false);
            return;
        }

        const trimmed = url.trim();
        if (!trimmed || !isValidManagementUrl(trimmed)) {
            setUrlError(t("settings.general.management.urlError"));
            urlRef.current?.focus();
            return;
        }

        const target = normalizeManagementUrl(trimmed);
        setChecking(true);
        const reachable = await checkManagementUrlReachable(target);
        setChecking(false);
        if (!reachable && !unreachable) {
            setUnreachable(true);
            return;
        }

        onCreate(sanitized, target);
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
                maxWidthClass="max-w-md"
                showClose={false}
                className="py-7"
                onOpenAutoFocus={(e) => e.preventDefault()}
            >
                <form onSubmit={handleSubmit}>
                    <div className="flex flex-col gap-6 px-7">
                        <div className="flex flex-col gap-2">
                            <div className={"pl-1"}>
                                <Label as={"div"} className={"mb-0.5"}>
                                    {t("profile.dialog.nameLabel")}
                                </Label>
                                <HelpText margin={false}>
                                    {t("profile.dialog.description")}
                                </HelpText>
                            </div>
                            <Input
                                ref={nameRef}
                                autoFocus
                                placeholder={t("profile.dialog.placeholder")}
                                value={name}
                                onChange={(e) => handleNameChange(e.target.value)}
                                error={nameError ?? undefined}
                                maxLength={MAX_PROFILE_NAME_LEN}
                                spellCheck={false}
                                autoComplete="off"
                                autoCapitalize="off"
                            />
                        </div>

                        {!managedManagementUrl && (
                            <div className="flex flex-col gap-2">
                                <div className={"pl-1"}>
                                    <Label as={"div"} className={"mb-0.5"}>
                                        {t("settings.general.management.label")}
                                    </Label>
                                    <HelpText margin={false}>
                                        {t("profile.dialog.managementHelp")}
                                    </HelpText>
                                </div>
                                <div className="flex flex-col gap-3">
                                    <ManagementServerSwitch
                                        value={mode}
                                        onChange={setMode}
                                        fullWidth
                                    />
                                    {mode === ManagementMode.SelfHosted && (
                                        <Input
                                            ref={urlRef}
                                            autoFocus
                                            placeholder={t(
                                                "settings.general.management.urlPlaceholder",
                                            )}
                                            value={url}
                                            onChange={(e) => setUrl(e.target.value)}
                                            error={urlInputError}
                                            warning={urlInputWarning}
                                            spellCheck={false}
                                            autoComplete="off"
                                            autoCorrect="off"
                                            autoCapitalize="off"
                                        />
                                    )}
                                </div>
                            </div>
                        )}

                        <DialogActions className={"flex-row items-center justify-end gap-2.5 pt-2"}>
                            <Button
                                type="button"
                                variant={"secondary"}
                                size={"xs2"}
                                disabled={checking}
                                onClick={() => onOpenChange(false)}
                            >
                                {t("common.cancel")}
                            </Button>
                            <Button
                                type="submit"
                                variant={"primary"}
                                size={"xs2"}
                                loading={checking}
                            >
                                {t("profile.dialog.submit")}
                            </Button>
                        </DialogActions>
                    </div>
                </form>
            </Dialog.Content>
        </Dialog.Root>
    );
};
