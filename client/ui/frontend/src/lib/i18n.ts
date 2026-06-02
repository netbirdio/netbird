import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import { Events } from "@wailsio/runtime";

import { Preferences, I18n } from "@bindings/services";
import { LanguageCode } from "@bindings/i18n/models.js";

// Vite glob-imports every shipped bundle at build time. The locales tree
// lives outside `frontend/` (at `client/ui/i18n/locales`) so the Go tray
// and the React app share one JSON source. Adding a language only
// requires dropping the new folder there and the row in `_index.json` —
// no edit to this file. The `eager: true` import keeps the bundles
// inlined in the main JS chunk, same shape as a static import. Path is
// relative on purpose — alias-based globs (`@/…`) silently resolve to an
// empty match in some Vite dev-mode setups. `server.fs.allow` in
// `vite.config.ts` whitelists the parent directory so the dev server
// serves the JSON.
const bundleModules = import.meta.glob<Record<string, string>>(
    "../../../i18n/locales/*/common.json",
    { eager: true, import: "default" },
);

const resources: Record<string, { common: Record<string, string> }> = {};
for (const path in bundleModules) {
    const match = path.match(/locales\/([^/]+)\/common\.json$/);
    if (match) {
        resources[match[1]] = { common: bundleModules[path] };
    }
}

// detectBrowserLanguage walks navigator.language + navigator.languages
// and returns the first shipped bundle that matches. We try an exact
// case-insensitive match first (so "en-GB" picks the en-GB bundle when
// shipped), then fall back to the base code ("de" from "de-DE"). Returns
// null when nothing matches, so the caller can fall back to English.
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

// initI18n is awaited from app.tsx before the first render. The Go-side
// preferences.Store returns an empty language code when no preference has
// ever been persisted — that's the signal for first-run browser-locale
// detection. We pick a shipped bundle that matches navigator.language /
// navigator.languages (falling back to "en" when nothing matches) and
// fire-and-forget the persist via Preferences.SetLanguage so subsequent
// launches read the value back without re-detecting.
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
    } catch {
        // Daemon / preferences store unreachable — fall through with "en".
    }

    if (firstRun) {
        // Fire-and-forget: the chosen language already drives this session;
        // persisting just locks it in so the next launch skips detection.
        void Preferences.SetLanguage(language as LanguageCode).catch(() => {});
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

    // The event name + payload type come from Wails' generated module
    // augmentation (bindings/.../wails/v3/internal/eventdata.d.ts) which
    // extends @wailsio/runtime's CustomEvents interface, so e.data is
    // typed as UIPreferences without any hand-written cast.
    Events.On("netbird:preferences:changed", (e) => {
        const next = e.data?.language;
        if (next && next !== i18next.language) {
            void i18next.changeLanguage(next);
        }
    });
}

export async function loadLanguages() {
    return I18n.Languages();
}

export default i18next;
