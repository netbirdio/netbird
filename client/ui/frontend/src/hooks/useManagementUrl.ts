import { useEffect, useRef, useState } from "react";
import { warningDialog } from "@/lib/dialogs.ts";
import i18next from "@/lib/i18n";
import { useSettings } from "@/contexts/SettingsContext.tsx";

export enum ManagementMode {
    Cloud = "cloud",
    SelfHosted = "selfhosted",
}

export const CLOUD_MANAGEMENT_URL = "https://api.netbird.io:443";

function normalizeManagementUrl(input: string): string {
    const trimmed = input.trim();
    if (!trimmed) return "";
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return `https://${trimmed}`;
}

const URL_PATTERN = new RegExp(
    "^(https?:\\/\\/)?" +
        "((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|localhost|" +
        "((\\d{1,3}\\.){3}\\d{1,3}))" +
        "(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*" +
        "(\\?[;&a-z\\d%_.~+=-]*)?" +
        "(\\#[-a-z\\d_]*)?$",
    "i",
);

function isValidManagementUrl(input: string): boolean {
    const trimmed = input.trim();
    if (!trimmed) return false;
    return URL_PATTERN.test(trimmed);
}

function modeFromUrl(url: string): ManagementMode {
    return url === CLOUD_MANAGEMENT_URL ? ManagementMode.Cloud : ManagementMode.SelfHosted;
}

export function useManagementUrl() {
    const { config, saveField } = useSettings();
    const [mode, setModeState] = useState<ManagementMode>(
        modeFromUrl(config.managementUrl),
    );
    const [url, setUrl] = useState(
        config.managementUrl === CLOUD_MANAGEMENT_URL ? "" : config.managementUrl,
    );
    // Guard against double-showing the cloud-switch confirmation when the
    // user toggles the segmented control multiple times before the prior
    // Dialogs.Warning promise resolves. Without it each click queues a
    // fresh native dialog and the user sees them stack up.
    const switchConfirmOpenRef = useRef(false);

    useEffect(() => {
        setModeState(modeFromUrl(config.managementUrl));
        if (config.managementUrl !== CLOUD_MANAGEMENT_URL) {
            setUrl(config.managementUrl);
        }
    }, [config.managementUrl]);

    const setMode = (next: ManagementMode) => {
        if (
            next === ManagementMode.Cloud &&
            config.managementUrl !== CLOUD_MANAGEMENT_URL
        ) {
            // Switching from a self-hosted management server to NetBird Cloud
            // re-points the client at a different deployment and forces a
            // reconnect/re-login. Confirm before applying.
            if (switchConfirmOpenRef.current) return;
            switchConfirmOpenRef.current = true;
            const cancelLabel = i18next.t("common.cancel");
            const confirmLabel = i18next.t("settings.general.management.switchCloudConfirm");
            void warningDialog({
                Title: i18next.t("settings.general.management.switchCloudTitle"),
                Message: i18next.t("settings.general.management.switchCloudMessage"),
                Buttons: [
                    { Label: cancelLabel, IsCancel: true, IsDefault: true },
                    { Label: confirmLabel },
                ],
            })
                .then((result) => {
                    if (result !== confirmLabel) return;
                    setModeState(ManagementMode.Cloud);
                    void saveField("managementUrl", CLOUD_MANAGEMENT_URL);
                })
                .finally(() => {
                    switchConfirmOpenRef.current = false;
                });
            return;
        }
        setModeState(next);
    };

    const normalizedUrl = normalizeManagementUrl(url);
    const urlValid = isValidManagementUrl(url);
    const targetUrl =
        mode === ManagementMode.Cloud ? CLOUD_MANAGEMENT_URL : normalizedUrl;
    const dirty = targetUrl !== config.managementUrl;
    const showError =
        mode === ManagementMode.SelfHosted && url.trim() !== "" && !urlValid;
    const canSave = dirty && (mode === ManagementMode.Cloud || urlValid);
    const displayUrl = mode === ManagementMode.Cloud ? CLOUD_MANAGEMENT_URL : url;

    const save = () => saveField("managementUrl", targetUrl);

    return {
        mode,
        setMode,
        url,
        setUrl,
        displayUrl,
        showError,
        canSave,
        save,
    };
}
