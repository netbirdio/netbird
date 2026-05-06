import {
    ConnectionState,
    NetBirdConnectToggle,
} from "@/components/NetBirdConnectToggle.tsx";

export const ConnectionStatus = () => {
    return (
        <div className={"flex flex-col items-center"}>
            <NetBirdConnectToggle state={ConnectionState.Connected} />
            <h1
                className={
                    "text-base font-medium mt-8 text-nb-gray-200 tracking-wide"
                }
            >
                Connected
            </h1>
            <p className={"font-mono text-xs text-nb-gray-300 mt-1"}>
                peer-hostname.netbird.cloud
            </p>
            <p className={"font-mono text-xs text-nb-gray-300 mt-0.5"}>
                192.168.0.1
            </p>
        </div>
    );
};
