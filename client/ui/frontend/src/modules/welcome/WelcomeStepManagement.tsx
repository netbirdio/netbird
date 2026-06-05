import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/buttons/Button";
import { DialogActions } from "@/components/dialog/DialogActions";
import { DialogDescription } from "@/components/dialog/DialogDescription";
import { DialogHeading } from "@/components/dialog/DialogHeading";
import { Input } from "@/components/inputs/Input";
import { ManagementServerSwitch } from "@/components/ManagementServerSwitch";
import {
    CLOUD_MANAGEMENT_URL,
    ManagementMode,
    checkManagementUrlReachable,
    isCloudManagementUrl,
    isValidManagementUrl,
    normalizeManagementUrl,
} from "@/hooks/useManagementUrl";
import { cn } from "@/lib/cn.ts";
import { isMacOS } from "@/lib/platform.ts";

type WelcomeStepManagementProps = {
    // initialUrl is the management URL the daemon is already configured
    // with (empty / cloud-default both render as Cloud selected).
    initialUrl: string;
    // onContinue is invoked with the URL the user wants to persist. The
    // parent owns the actual Settings.SetConfig call so the dialog stays
    // free of context dependencies.
    onContinue: (url: string) => Promise<void>;
};

export function WelcomeStepManagement({ initialUrl, onContinue }: WelcomeStepManagementProps) {
    const { t } = useTranslation();
    const startsCloud = isCloudManagementUrl(initialUrl);
    const [mode, setMode] = useState<ManagementMode>(
        startsCloud ? ManagementMode.Cloud : ManagementMode.SelfHosted,
    );
    const [url, setUrl] = useState(startsCloud ? "" : initialUrl);
    const [syntaxError, setSyntaxError] = useState<string | null>(null);
    // unreachable: soft warning. Continue stays enabled — user can confirm
    // they typed it right and proceed (matches self-hosted-behind-internal-
    // DNS / VPN scenarios where the in-app fetch would false-negative).
    const [unreachable, setUnreachable] = useState(false);
    const [checking, setChecking] = useState(false);

    const trimmedUrl = url.trim();
    const syntaxValid = mode === ManagementMode.Cloud || isValidManagementUrl(trimmedUrl);
    // Continue is no longer disabled for an empty / invalid self-hosted
    // URL; a Continue click in that state focuses the input and renders
    // an inline error so the user actively notices what's missing.
    const inputRef = useRef<HTMLInputElement | null>(null);

    // Reset inline error/warning whenever the user edits the URL or flips
    // mode — otherwise the warning lingers next to a just-corrected value.
    useEffect(() => {
        setSyntaxError(null);
        setUnreachable(false);
    }, [url, mode]);

    const handleContinue = useCallback(async () => {
        if (checking) return;
        if (mode === ManagementMode.SelfHosted && (!trimmedUrl || !syntaxValid)) {
            // Empty or syntactically invalid URL — Continue stays enabled
            // so the click registers; surface the error inline and focus
            // the input so the user has somewhere to fix it.
            setSyntaxError(t("welcome.management.urlInvalid"));
            inputRef.current?.focus();
            return;
        }
        const target =
            mode === ManagementMode.Cloud
                ? CLOUD_MANAGEMENT_URL
                : normalizeManagementUrl(trimmedUrl);
        if (mode === ManagementMode.SelfHosted) {
            setChecking(true);
            const reachable = await checkManagementUrlReachable(target);
            setChecking(false);
            // First failed check: show soft warning + bail. A second click
            // with the same URL skips the check (unreachable still true)
            // so the user can proceed if they're sure.
            if (!reachable && !unreachable) {
                setUnreachable(true);
                return;
            }
        }
        try {
            await onContinue(target);
        } catch (e) {
            // Parent surfaces save errors via errorDialog; keep a console
            // breadcrumb but don't double-render.
            console.error("save management url:", e);
        }
    }, [checking, mode, syntaxValid, trimmedUrl, unreachable, onContinue, t]);

    // Syntax problems are hard errors (red); an unreachable-but-valid URL is
    // a soft, non-blocking caveat (orange).
    const inputError = syntaxError ?? undefined;
    const inputWarning = useMemo(
        () => (!syntaxError && unreachable ? t("welcome.management.urlUnreachable") : undefined),
        [syntaxError, unreachable, t],
    );

    return (
        <>
            <div className={cn("flex flex-col items-center gap-1", isMacOS() && "mt-4")}>
                <DialogHeading align={"left"}>{t("welcome.management.title")}</DialogHeading>
                <DialogDescription align={"left"}>
                    {t("welcome.management.description")}
                </DialogDescription>
            </div>

            <div className={"wails-no-draggable w-full"}>
                <ManagementServerSwitch value={mode} onChange={setMode} fullWidth />
            </div>

            {mode === ManagementMode.SelfHosted && (
                <div className={"wails-no-draggable w-full text-left"}>
                    <Input
                        ref={inputRef}
                        placeholder={t("welcome.management.urlPlaceholder")}
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        error={inputError}
                        warning={inputWarning}
                        autoFocus
                    />
                </div>
            )}

            <DialogActions>
                <Button
                    variant={"primary"}
                    size={"md"}
                    className={"w-full"}
                    onClick={handleContinue}
                    disabled={checking}
                >
                    {checking ? t("welcome.management.checking") : t("welcome.continue")}
                </Button>
            </DialogActions>
        </>
    );
}
