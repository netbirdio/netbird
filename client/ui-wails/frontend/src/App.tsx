import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import Layout from "./Layout";
import Status from "./pages/Status";
import Settings from "./pages/Settings";
import Networks from "./pages/Networks";
import Peers from "./pages/Peers";
import Profiles from "./pages/Profiles";
import Debug from "./pages/Debug";
import Update from "./pages/Update";
import QuickActions from "./pages/QuickActions";
import LoginUrl from "./pages/LoginUrl";

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/quick" element={<QuickActions />} />
        <Route path="/login" element={<LoginUrl />} />
        <Route path="/update" element={<Update />} />
        <Route element={<Layout />}>
          <Route index element={<Status />} />
          <Route path="peers" element={<Peers />} />
          <Route path="networks" element={<Networks />} />
          <Route path="profiles" element={<Profiles />} />
          <Route path="settings" element={<Settings />} />
          <Route path="debug" element={<Debug />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
