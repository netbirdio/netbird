import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import QuickActions from "@/screens/QuickActions.tsx";
import SessionExpiredDialog from "@/modules/authentication/SessionExpiredDialog.tsx";
import SessionAboutToExpireDialog from "@/modules/authentication/SessionAboutToExpireDialog.tsx";
import Update from "@/screens/Update.tsx";
import { AppLayout } from "@/layouts/AppLayout.tsx";
import { SettingsLayout } from "@/layouts/SettingsLayout.tsx";
import { Main } from "@/layouts/Main.tsx";
import { Settings } from "@/modules/settings/Settings.tsx";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { welcome } from "@/lib/welcome";
import WaitingForBrowserDialog from "@/modules/authentication/WaitingForBrowserDialog.tsx";
import { initI18n } from "@/lib/i18n";

welcome();

initI18n()
    .catch((e) => {
        // Surface init failures in the console so a misconfigured glob
        // doesn't quietly blank the UI; render anyway with i18next in
        // whatever state it ended up in (t() will fall back to keys).
        console.error("i18n init failed:", e);
    })
    .finally(() => {
        ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
        <React.StrictMode>
            <SkeletonTheme baseColor={"#25282d"} highlightColor={"#33373e"}>
                <HashRouter>
                    <Routes>
                        <Route path="/quick" element={<QuickActions />} />
                        <Route path="/browser-login" element={<WaitingForBrowserDialog />} />
                        <Route path="/update" element={<Update />} />
                        <Route path="/session-expired" element={<SessionExpiredDialog />} />
                        <Route path="/session-about-to-expire" element={<SessionAboutToExpireDialog />} />
                        <Route element={<SettingsLayout />}>
                            <Route path="settings" element={<Settings />} />
                        </Route>
                        <Route element={<AppLayout />}>
                            <Route index element={<Main />} />
                            <Route
                                path="*"
                                element={<Navigate to={"/"} replace />}
                            />
                        </Route>
                    </Routes>
                </HashRouter>
            </SkeletonTheme>
        </React.StrictMode>,
        );
    });
