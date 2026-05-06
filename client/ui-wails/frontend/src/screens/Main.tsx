import { ConnectionStatus } from "@/layouts/ConnectionStatus.tsx";
import { Header } from "@/layouts/Header.tsx";
import { Navigation } from "@/layouts/Navigation.tsx";
import { PeersModule } from "@/modules/peers/PeersModule.tsx";

type Props = {

};
export const Main = ({}: Props) => {
    return (
        <div className={"flex h-full p-4 gap-4 min-h-0"}>
            <div className={"flex flex-col max-w-xs w-full shrink-0 items-center"}>
                <Header />
                <ConnectionStatus />
                <Navigation />
            </div>

            <div className={"flex-1 min-h-0 min-w-0 flex flex-col bg-nb-gray-935 rounded-xl border border-nb-gray-900"}>
                <PeersModule />
            </div>
        </div>

    );
};
