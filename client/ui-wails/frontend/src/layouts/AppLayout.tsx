import { Outlet } from "react-router-dom";
import { Header } from "@/layouts/Header.tsx";

export const AppLayout = () => {
    return (
        <div className={"flex h-full flex-col"}>
            <Header />
            <Outlet />
        </div>
    );
};
