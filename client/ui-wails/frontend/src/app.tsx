import React from "react";
import ReactDOM from "react-dom/client";
import "./globals.css";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import QuickActions from "@/screens/QuickActions.tsx";
import LoginUrl from "@/screens/LoginUrl.tsx";
import Update from "@/screens/Update.tsx";
import Layout from "@/layout.tsx";
import Peers from "@/screens/Peers.tsx";
import Networks from "@/screens/Networks.tsx";
import Profiles from "@/screens/Profiles.tsx";
import Settings from "@/screens/Settings.tsx";
import Debug from "@/screens/Debug.tsx";
import {Main} from "@/screens/Main.tsx";
import { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
      <SkeletonTheme baseColor={"#25282d"} highlightColor={"#33373e"}>
          <HashRouter>
              <Routes>
                  <Route path="/quick" element={<QuickActions />} />
                  <Route path="/login" element={<LoginUrl />} />
                  <Route path="/update" element={<Update />} />
                  <Route element={<Layout />}>
                      <Route index element={<Main />} />
                      <Route path="peers" element={<Peers />} />
                      <Route path="networks" element={<Networks />} />
                      <Route path="profiles" element={<Profiles />} />
                      <Route path="settings" element={<Settings />} />
                      <Route path="debug" element={<Debug />} />
                      <Route path="*" element={<Navigate to="/" replace />} />
                  </Route>
              </Routes>
          </HashRouter>
      </SkeletonTheme>
  </React.StrictMode>,
);
