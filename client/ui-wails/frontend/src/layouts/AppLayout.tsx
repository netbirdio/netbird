import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";
import { AutoUpdate } from "@/modules/auto-update/AutoUpdate.tsx";
import { ProfileProvider } from "@/modules/profile/ProfileContext.tsx";

export const AppLayout = () => {
    return (
        <ProfileProvider>
            <div className={"relative flex h-full flex-col"}>
                <Header />
                <Outlet />
                <AutoUpdate />
            </div>
        </ProfileProvider>
    );
};
