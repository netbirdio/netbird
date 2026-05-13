import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import QuickActions from "@/screens/QuickActions.tsx";
import SessionExpired from "@/pages/SessionExpired.tsx";
import Update from "@/screens/Update.tsx";
import { AppLayout } from "@/layouts/AppLayout.tsx";
import { SettingsLayout } from "@/layouts/SettingsLayout.tsx";
import { Main } from "@/layouts/Main.tsx";
import { Settings } from "@/modules/settings/Settings.tsx";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { welcome } from "@/lib/welcome";
import Login from "@/pages/Login.tsx";

welcome();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
        <SkeletonTheme baseColor={"#25282d"} highlightColor={"#33373e"}>
            <HashRouter>
                <Routes>
                    <Route path="/quick" element={<QuickActions />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/update" element={<Update />} />
                    <Route path="/session-expired" element={<SessionExpired />} />
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
