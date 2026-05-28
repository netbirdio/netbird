import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import SessionExpiredDialog from "@/modules/session/SessionExpiredDialog.tsx";
import SessionAboutToExpireDialog from "@/modules/session/SessionAboutToExpireDialog.tsx";
import UpdateInProgressDialog from "@/modules/auto-update/UpdateInProgressDialog.tsx";
import { AppLayout } from "@/layouts/AppLayout.tsx";
import { MainPage } from "@/modules/main/MainPage.tsx";
import { SettingsPage } from "@/modules/settings/SettingsPage.tsx";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { welcome } from "@/lib/welcome";
import LoginWaitingForBrowserDialog from "@/modules/login/LoginWaitingForBrowserDialog.tsx";
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
                        <Route path="dialog">
                            <Route path="browser-login" element={<LoginWaitingForBrowserDialog />} />
                            <Route path="install-progress" element={<UpdateInProgressDialog />} />
                            <Route path="session-expired" element={<SessionExpiredDialog />} />
                            <Route path="session-about-to-expire" element={<SessionAboutToExpireDialog />} />
                        </Route>
                        <Route element={<AppLayout />}>
                            <Route index element={<MainPage />} />
                            <Route path="settings" element={<SettingsPage />} />
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
