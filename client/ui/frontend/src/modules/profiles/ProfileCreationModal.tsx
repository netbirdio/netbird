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

type Props = {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    // onCreate receives the sanitized profile name and the management URL the
    // user picked (the cloud default for Cloud mode, the normalized self-
    // hosted URL otherwise).
    onCreate: (name: string, managementUrl: string) => void;
};

// Mirror of the daemon's profilemanager.sanitizeProfileName rule
// (client/internal/profilemanager/profilemanager.go): only letters, digits,
// `_` and `-` survive on the Go side. We additionally lowercase and convert
// spaces to `-` so what the user sees in the input is exactly what the
// daemon will store — otherwise the daemon silently sanitizes ("my profile"
// → "myprofile") while the UI keeps the raw name in flight, which spawns a
// ghost row and breaks subsequent delete.
const sanitizeProfileInput = (value: string): string =>
    value
        .toLowerCase()
        .replace(/\s+/g, "-")
        .replace(/[^a-z0-9_-]/g, "");

export const ProfileCreationModal = ({ open, onOpenChange, onCreate }: Props) => {
    const { t } = useTranslation();
    const [name, setName] = useState("");
    const [nameError, setNameError] = useState<string | null>(null);
    const nameRef = useRef<HTMLInputElement>(null);

    const [mode, setMode] = useState<ManagementMode>(ManagementMode.Cloud);
    const [url, setUrl] = useState("");
    const [urlError, setUrlError] = useState<string | null>(null);
    // unreachable: soft warning. A second submit with the same URL proceeds
    // anyway (matches the onboarding management step's behaviour for self-
    // hosted servers behind internal DNS / VPN).
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

    // Reset the URL warnings whenever the user edits the URL or flips mode —
    // otherwise a stale warning lingers next to a just-corrected value.
    useEffect(() => {
        setUrlError(null);
        setUnreachable(false);
    }, [url, mode]);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        if (checking) return;

        const sanitized = sanitizeProfileInput(name);
        if (sanitized.length === 0) {
            setNameError(t("profile.dialog.required"));
            nameRef.current?.focus();
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
        // First failed check: soft warning + bail. A second submit with the
        // same URL skips re-checking (unreachable still true) so the user can
        // proceed if they're sure.
        if (!reachable && !unreachable) {
            setUnreachable(true);
            return;
        }

        onCreate(sanitized, target);
        onOpenChange(false);
    };

    const handleNameChange = (value: string) => {
        setName(sanitizeProfileInput(value));
        if (nameError) setNameError(null);
    };

    // Live syntactic feedback: flag a non-empty, malformed URL as the user
    // types instead of waiting for submit. Empty is not an error yet (handled
    // on submit); the unreachable soft-warning only applies once syntax is OK.
    const trimmedUrl = url.trim();
    const showUrlSyntaxError =
        mode === ManagementMode.SelfHosted && trimmedUrl !== "" && !isValidManagementUrl(trimmedUrl);
    const urlInputError = showUrlSyntaxError
        ? t("settings.general.management.urlError")
        : (urlError ?? undefined);
    // Soft, non-blocking caveat (orange) — only when the URL is otherwise OK.
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
                                maxLength={64}
                                spellCheck={false}
                                autoComplete="off"
                                autoCapitalize="off"
                            />
                        </div>

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
                                <ManagementServerSwitch value={mode} onChange={setMode} fullWidth />
                                {mode === ManagementMode.SelfHosted && (
                                    <Input
                                        ref={urlRef}
                                        autoFocus
                                        placeholder={t("settings.general.management.urlPlaceholder")}
                                        value={url}
                                        onChange={(e) => setUrl(e.target.value)}
                                        error={urlInputError}
                                        warning={urlInputWarning}
                                        spellCheck={false}
                                        autoComplete="off"
                                        autoCapitalize="off"
                                    />
                                )}
                            </div>
                        </div>

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
