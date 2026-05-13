import { useEffect, useState } from "react";
import { Dialogs } from "@wailsio/runtime";
import { useSettings } from "@/modules/settings/SettingsContext.tsx";

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
            void Dialogs.Warning({
                Title: "Switch to NetBird Cloud?",
                Message:
                    "This will disconnect from your self-hosted management server and reconnect to NetBird Cloud. You may need to log in again.",
                Buttons: [
                    { Label: "Cancel", IsCancel: true, IsDefault: true },
                    { Label: "Switch to Cloud" },
                ],
            }).then((result) => {
                if (result !== "Switch to Cloud") return;
                setModeState(ManagementMode.Cloud);
                void saveField("managementUrl", CLOUD_MANAGEMENT_URL);
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
