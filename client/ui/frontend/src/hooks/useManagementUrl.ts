import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSettings } from "@/contexts/SettingsContext.tsx";
import { useConfirm } from "@/contexts/DialogContext.tsx";

export const CLOUD_MANAGEMENT_URL = "https://api.netbird.io:443";
const CLOUD_MANAGEMENT_URLS = new Set([
    CLOUD_MANAGEMENT_URL,
    "https://api.wiretrustee.com:443", // legacy cloud endpoint
]);

export function isNetbirdCloud(url: string): boolean {
    if (!url || url.trim() === "") return true;
    return CLOUD_MANAGEMENT_URLS.has(url);
}

// Matches http(s)://host[:port][/path][?query][#fragment]; host = domain, localhost, or IPv4.
// Syntactic validation only — reachability is checked via checkManagementUrlReachable.
export const URL_PATTERN = new RegExp(
    String.raw`^(https?:\/\/)?` +
        String.raw`((([a-z\d]([a-z\d-]*[a-z\d])?)\.)+[a-z]{2,}|localhost|` +
        String.raw`((\d{1,3}\.){3}\d{1,3}))` +
        String.raw`(\:\d+)?(\/[-a-z\d%_.~+]*)*` +
        String.raw`(\?[;&a-z\d%_.~+=-]*)?` +
        String.raw`(\#[-a-z\d_]*)?$`,
    "i",
);

export function normalizeManagementUrl(input: string): string {
    const trimmed = input.trim();
    if (!trimmed) return "";
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return `https://${trimmed}`;
}

export function isValidManagementUrl(input: string): boolean {
    const trimmed = input.trim();
    if (!trimmed) return false;
    return URL_PATTERN.test(trimmed);
}

// Can false-negative for self-hosted behind internal DNS / self-signed certs — treat as a soft warning, not a hard block.
export async function checkManagementUrlReachable(
    url: string,
    timeoutMs: number = 5000,
): Promise<boolean> {
    const target = normalizeManagementUrl(url);
    if (!target) return false;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        await fetch(target, { method: "GET", mode: "no-cors", signal: controller.signal });
        return true;
    } catch {
        return false;
    } finally {
        clearTimeout(timer);
    }
}

export enum ManagementMode {
    Cloud = "cloud",
    SelfHosted = "selfhosted",
}

function modeFromUrl(url: string): ManagementMode {
    return isNetbirdCloud(url) ? ManagementMode.Cloud : ManagementMode.SelfHosted;
}

export function useManagementUrl() {
    const { t } = useTranslation();
    const confirm = useConfirm();
    const { config, saveField } = useSettings();
    const [modeState, setModeState] = useState<ManagementMode>(modeFromUrl(config.managementUrl));
    const [url, setUrl] = useState(
        isNetbirdCloud(config.managementUrl) ? "" : config.managementUrl,
    );
    const [checking, setChecking] = useState(false);
    const [unreachable, setUnreachable] = useState(false);

    useEffect(() => {
        setModeState(modeFromUrl(config.managementUrl));
        if (!isNetbirdCloud(config.managementUrl)) {
            setUrl(config.managementUrl);
        }
    }, [config.managementUrl]);

    useEffect(() => {
        setUnreachable(false);
    }, [url, modeState]);

    const setMode = async (next: ManagementMode) => {
        if (next === ManagementMode.Cloud && !isNetbirdCloud(config.managementUrl)) {
            const ok = await confirm({
                title: t("settings.general.management.switchCloudTitle"),
                description: t("settings.general.management.switchCloudMessage"),
                confirmLabel: t("settings.general.management.switchCloudConfirm"),
            });
            if (!ok) return;
            setModeState(ManagementMode.Cloud);
            saveField("managementUrl", CLOUD_MANAGEMENT_URL).catch((err: unknown) =>
                console.error("save managementUrl failed", err),
            );
            return;
        }
        setModeState(next);
    };

    const normalizedUrl = normalizeManagementUrl(url);
    const urlValid = isValidManagementUrl(url);
    const targetUrl = modeState === ManagementMode.Cloud ? CLOUD_MANAGEMENT_URL : normalizedUrl;
    const dirty = targetUrl !== config.managementUrl;
    const showError = modeState === ManagementMode.SelfHosted && url.trim() !== "" && !urlValid;
    const canSave = dirty && (modeState === ManagementMode.Cloud || urlValid);
    const displayUrl = modeState === ManagementMode.Cloud ? CLOUD_MANAGEMENT_URL : url;

    const save = async () => {
        if (modeState === ManagementMode.SelfHosted && !unreachable) {
            setChecking(true);
            const reachable = await checkManagementUrlReachable(targetUrl);
            setChecking(false);
            if (!reachable) {
                setUnreachable(true);
                return;
            }
        }
        await saveField("managementUrl", targetUrl);
        setUnreachable(false);
    };

    return {
        mode: modeState,
        setMode,
        url,
        setUrl,
        displayUrl,
        showError,
        canSave,
        save,
        checking,
        unreachable,
    };
}
