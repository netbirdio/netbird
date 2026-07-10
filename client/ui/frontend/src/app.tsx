import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import SessionExpirationDialog from "@/modules/session/SessionExpirationDialog.tsx";
import UpdateInProgressDialog from "@/modules/auto-update/UpdateInProgressDialog.tsx";
import WelcomeDialog from "@/modules/welcome/WelcomeDialog.tsx";
import ErrorDialog from "@/modules/error/ErrorDialog.tsx";
import { AppLayout } from "@/layouts/AppLayout.tsx";
import { MainPage } from "@/modules/main/MainPage.tsx";
import { SettingsPage } from "@/modules/settings/SettingsPage.tsx";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { welcome } from "@/lib/welcome";
import LoginWaitingForBrowserDialog from "@/modules/login/LoginWaitingForBrowserDialog.tsx";
import { initI18n } from "@/lib/i18n";
import { initPlatform } from "@/lib/platform";
import { initLogForwarding } from "@/lib/logs";
import { initStallWatch } from "@/lib/stallwatch";

// Must run first so even init-time logs reach the Go log pipeline.
initLogForwarding();

initStallWatch();

welcome();

Promise.all([
    initI18n().catch((e) => {
        console.error("i18n init failed:", e);
    }),
    initPlatform().catch((e) => {
        console.error("platform init failed:", e);
    }),
]).finally(() => {
    ReactDOM.createRoot(document.getElementById("root")!).render(
        <React.StrictMode>
            <SkeletonTheme baseColor={"#25282d"} highlightColor={"#33373e"}>
                <HashRouter>
                    <Routes>
                        <Route path={"dialog"}>
                            <Route
                                path={"browser-login"}
                                element={<LoginWaitingForBrowserDialog />}
                            />
                            <Route path={"install-progress"} element={<UpdateInProgressDialog />} />
                            <Route
                                path={"session-expiration"}
                                element={<SessionExpirationDialog />}
                            />
                            <Route path={"welcome"} element={<WelcomeDialog />} />
                            <Route path={"error"} element={<ErrorDialog />} />
                        </Route>
                        <Route element={<AppLayout />}>
                            <Route index element={<MainPage />} />
                            <Route path={"settings"} element={<SettingsPage />} />
                            <Route path={"*"} element={<Navigate to={"/"} replace />} />
                        </Route>
                    </Routes>
                </HashRouter>
            </SkeletonTheme>
        </React.StrictMode>,
    );
});
