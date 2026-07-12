import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import { Events } from "@wailsio/runtime";

import { Preferences, I18n } from "@bindings/services";
import { type LanguageCode } from "@bindings/i18n/models.js";

// Relative path on purpose — alias globs (`@/…`) silently match nothing in some Vite dev setups.
type BundleEntry = { message: string; description?: string };
const bundleModules = import.meta.glob<Record<string, BundleEntry>>(
    "../../../i18n/locales/*/common.json",
    { eager: true, import: "default" },
);

const resources: Record<string, { common: Record<string, string> }> = {};
for (const path in bundleModules) {
    const match = /locales\/([^/]+)\/common\.json$/.exec(path);
    if (match) {
        const entries = bundleModules[path];
        const messages: Record<string, string> = {};
        for (const key in entries) {
            messages[key] = entries[key].message;
        }
        resources[match[1]] = { common: messages };
    }
}

function detectBrowserLanguage(available: string[]): string | null {
    const tags = [navigator.language, ...(navigator.languages ?? [])].filter(
        (tag): tag is string => typeof tag === "string" && tag.length > 0,
    );
    const byLower = new Map(available.map((code) => [code.toLowerCase(), code]));
    for (const tag of tags) {
        const lower = tag.toLowerCase();
        const exact = byLower.get(lower);
        if (exact) return exact;
        const base = byLower.get(lower.split("-")[0]);
        if (base) return base;
    }
    return null;
}

// An empty persisted language code is the Go-side signal for first run.
export async function initI18n(): Promise<void> {
    const available = Object.keys(resources);
    let language = "en";
    let firstRun = false;
    try {
        const prefs = await Preferences.Get();
        if (prefs?.language) {
            language = prefs.language;
        } else {
            firstRun = true;
            language = detectBrowserLanguage(available) ?? "en";
        }
    } catch (e) {
        console.warn("read preferences for language failed, defaulting to en", e);
    }

    if (firstRun) {
        Preferences.SetLanguage(language as LanguageCode).catch((err: unknown) =>
            console.warn("persist detected language failed", err),
        );
    }

    await i18next.use(initReactI18next).init({
        lng: language,
        fallbackLng: "en",
        defaultNS: "common",
        ns: ["common"],
        resources,
        interpolation: {
            prefix: "{",
            suffix: "}",
            escapeValue: false,
        },
        returnNull: false,
    });

    syncDocumentLang();
    i18next.on("languageChanged", syncDocumentLang);

    Events.On("netbird:preferences:changed", (e) => {
        const next = e.data?.language;
        if (next && next !== i18next.language) {
            i18next.changeLanguage(next).catch((err: unknown) => {
                console.error("changeLanguage failed", err);
            });
        }
    });
}

function syncDocumentLang() {
    if (typeof document !== "undefined") {
        document.documentElement.lang = i18next.language;
    }
}

export async function loadLanguages() {
    return I18n.Languages();
}

export default i18next;
