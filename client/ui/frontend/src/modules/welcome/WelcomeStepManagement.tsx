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
    isNetbirdCloud,
    isValidManagementUrl,
    normalizeManagementUrl,
} from "@/hooks/useManagementUrl";
import { cn } from "@/lib/cn.ts";
import { isMacOS } from "@/lib/platform.ts";

type WelcomeStepManagementProps = {
    initialUrl: string;
    onContinue: (url: string) => Promise<void>;
};

export function WelcomeStepManagement({
    initialUrl,
    onContinue,
}: Readonly<WelcomeStepManagementProps>) {
    const { t } = useTranslation();
    const startsCloud = isNetbirdCloud(initialUrl);
    const [mode, setMode] = useState<ManagementMode>(
        startsCloud ? ManagementMode.Cloud : ManagementMode.SelfHosted,
    );
    const [url, setUrl] = useState(startsCloud ? "" : initialUrl);
    const [syntaxError, setSyntaxError] = useState<string | null>(null);
    const [unreachable, setUnreachable] = useState(false);
    const [checking, setChecking] = useState(false);

    const trimmedUrl = url.trim();
    const syntaxValid = mode === ManagementMode.Cloud || isValidManagementUrl(trimmedUrl);
    const inputRef = useRef<HTMLInputElement | null>(null);
    const initialMountRef = useRef(true);
    const initialSelfHostedRef = useRef(!startsCloud);

    useEffect(() => {
        setSyntaxError(null);
        setUnreachable(false);
    }, [url, mode]);

    useEffect(() => {
        if (initialMountRef.current && initialSelfHostedRef.current) {
            inputRef.current?.focus();
        }
        initialMountRef.current = false;
    }, []);

    const handleContinue = useCallback(async () => {
        if (checking) return;
        if (mode === ManagementMode.SelfHosted && (!trimmedUrl || !syntaxValid)) {
            setSyntaxError(t("welcome.management.urlInvalid"));
            inputRef.current?.focus();
            return;
        }
        const target =
            mode === ManagementMode.Cloud
                ? CLOUD_MANAGEMENT_URL
                : normalizeManagementUrl(trimmedUrl);
        if (mode === ManagementMode.SelfHosted && !unreachable) {
            setChecking(true);
            const reachable = await checkManagementUrlReachable(target);
            setChecking(false);
            if (!reachable) {
                setUnreachable(true);
                return;
            }
        }
        try {
            await onContinue(target);
        } catch (e) {
            console.error("save management url:", e);
        }
    }, [checking, mode, syntaxValid, trimmedUrl, unreachable, onContinue, t]);

    const inputError = syntaxError ?? undefined;
    const inputWarning = useMemo(
        () => (!syntaxError && unreachable ? t("welcome.management.urlUnreachable") : undefined),
        [syntaxError, unreachable, t],
    );

    return (
        <>
            <div className={cn("flex flex-col items-center gap-1", isMacOS() && "mt-4")}>
                <DialogHeading id={"nb-welcome-management-title"} align={"left"}>
                    {t("welcome.management.title")}
                </DialogHeading>
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
                        spellCheck={false}
                        autoComplete={"off"}
                        autoCorrect={"off"}
                        autoCapitalize={"off"}
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
