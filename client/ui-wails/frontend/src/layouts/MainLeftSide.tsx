import { ConnectionStatus } from "@/layouts/ConnectionStatus.tsx";
import { Header } from "@/layouts/Header.tsx";
import { Navigation } from "@/layouts/Navigation.tsx";

export type MainModule = "peers" | "settings";

type Props = {
    active: MainModule;
    onChange: (module: MainModule) => void;
};

export const MainLeftSide = ({ active, onChange }: Props) => {
    return (
        <div
            className={"flex flex-col max-w-xs w-full shrink-0 items-center"}
        >
            <Header
                settingsActive={active === "settings"}
                onSettingsClick={() =>
                    onChange(active === "settings" ? "peers" : "settings")
                }
            />
            <ConnectionStatus />
            <Navigation
                peersActive={active === "peers"}
                onPeersClick={() => {
                    if (active !== "peers") onChange("peers");
                }}
            />
        </div>
    );
};
