import { useTranslation } from "react-i18next";
import { cn } from "@/lib/cn";
import { Peer, PeerStatus } from "./types";

const DOT: Record<PeerStatus, string> = {
    connected: "bg-green-400",
    connecting: "bg-yellow-300 animate-pulse-slow",
    disconnected: "bg-nb-gray-500",
};

export const PeersList = ({ data }: { data: Peer[] }) => {
    const { t } = useTranslation();
    if (data.length === 0) {
        return (
            <div className={"py-12 text-center text-sm text-nb-gray-400"}>
                {t("peers.empty")}
            </div>
        );
    }

    return (
        <ul className={"flex flex-col"}>
            {data.map((peer) => (
                <li
                    key={peer.id}
                    className={"flex items-center gap-3 px-7 py-3 min-w-0"}
                >
                    <span
                        className={cn(
                            "h-2 w-2 rounded-full shrink-0",
                            DOT[peer.status],
                        )}
                        title={peer.status}
                    />
                    <span
                        className={
                            "text-[0.81rem] font-medium text-nb-gray-100 truncate"
                        }
                    >
                        {peer.fqdn}
                    </span>
                    <span
                        className={
                            "ml-auto text-xs font-mono text-nb-gray-400 shrink-0"
                        }
                    >
                        {peer.ip}
                    </span>
                </li>
            ))}
        </ul>
    );
};
