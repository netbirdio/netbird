import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import { Events } from "@wailsio/runtime";

import { Preferences, I18n } from "@bindings/services";

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

// initI18n is awaited from app.tsx before the first render. The Go-side
// preferences.Store returns the in-memory default "en" when no on-disk
// preferences file exists; if Get() rejects (daemon unreachable) we also
// fall through with "en" so the UI still renders.
export async function initI18n(): Promise<void> {
    let language = "en";
    try {
        const prefs = await Preferences.Get();
        if (prefs?.language) {
            language = prefs.language;
        }
    } catch {
        // Daemon / preferences store unreachable — fall through with "en".
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
