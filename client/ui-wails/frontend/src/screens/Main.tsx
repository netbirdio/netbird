import {ConnectionState, NetBirdConnectToggle} from "@/components/NetBirdConnectToggle.tsx";
import {
    BoltIcon,
    ChevronDown,
    CircleUserRound,
    Layers3Icon,
    MonitorSmartphoneIcon, SettingsIcon,
    SquareArrowUpRight
} from "lucide-react";

type Props = {

};
export const Main = ({}: Props) => {
    return (
        <div className={"flex"}>
            <div className={"flex flex-col max-w-xs w-full items-center mt-4"}>
                <div className={"w-full justify-between flex px-6 mb-14"}>
                    <div>
                        <div className={"h-8 rounded-md text-nb-gray-300 flex items-center gap-1.5 text-xs font-bold"}>
                            <div className={"h-7 w-7 flex items-center justify-center bg-purple-900 text-white rounded-md"}>
                                D
                            </div>
                            <div className={"whitespace-nowrap flex flex-col mt-0.5 ml-1"}>
                                <span>Default</span>
                                <span className={"text-[0.67rem] font-normal"}>eduard@netbird.io</span>
                            </div>

                            <ChevronDown size={14} className={""} />
                        </div>
                    </div>
                    <div>
                        <div className={"h-8 rounded-md text-nb-gray-300 flex items-center gap-1.5 text-xs font-bold px-2.5"}>
                            <SettingsIcon size={18} className={""} />
                        </div>
                    </div>
                </div>
                <NetBirdConnectToggle state={ConnectionState.Connected} />
                <h1 className={"text-base font-medium mt-8 text-nb-gray-200 tracking-wide"}>Connected</h1>
                <p className={"font-mono text-xs text-nb-gray-300 mt-1"}>peer-hostname.netbird.cloud</p>
                <p className={"font-mono text-xs text-nb-gray-300 mt-0.5"}>192.168.0.1</p>
                <nav className={"w-full px-6 py-8 flex flex-col gap-1"}>
                    <div className={"flex items-center gap-3 bg-nb-gray-930 p-1.5 rounded-lg"}>
                        <div className={"h-9 w-9 bg-nb-gray-800 rounded-md flex items-center justify-center"}>
                            <MonitorSmartphoneIcon size={15} className={"text-nb-gray-200"} />
                        </div>
                        <div>
                            <h2 className={"font-medium text-[0.81rem]"}>Peers</h2>
                            <p className={"text-xs font-medium text-nb-gray-300"}>13 of 16 Online</p>
                        </div>
                    </div>
                    <div className={"flex items-center gap-3 p-1.5 rounded-lg"}>
                        <div className={"h-9 w-9 bg-nb-gray-920 rounded-md flex items-center justify-center"}>
                            <Layers3Icon size={14} className={"text-nb-gray-400"} />
                        </div>
                        <div>
                            <h2 className={"font-medium text-[0.81rem]"}>Resources</h2>
                            <p className={"text-xs text-nb-gray-400 font-medium"}>13 of 16 Active</p>
                        </div>
                    </div>
                    <div className={"flex items-center gap-3 p-1.5 rounded-lg"}>
                        <div className={"h-9 w-9 bg-nb-gray-920 rounded-md flex items-center justify-center"}>
                            <SquareArrowUpRight size={14} className={"text-nb-gray-400"} />
                        </div>
                        <div>
                            <h2 className={"font-medium text-[0.81rem]"}>Exit Node Berlin</h2>
                            <p className={"text-xs text-nb-gray-400 font-medium"}>192.168...</p>
                        </div>
                    </div>
                </nav>
            </div>
            <div className={"bg-nb-gray-930 w-full m-6 rounded-lg"}>

            </div>
        </div>

    );
};
