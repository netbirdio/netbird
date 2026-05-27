import { ChevronRightIcon } from "lucide-react";
import type { PeerStatus } from "@bindings/services/models.js";
import { cn } from "@/lib/cn";
import { CopyToClipboard } from "@/components/CopyToClipboard";
import { latencyColor } from "./format";
import { usePeerDetail } from "./PeerDetailContext";

const dotClass = (connStatus: string): string => {
    switch (connStatus) {
        case "Connected":
            return "bg-green-400";
        case "Connecting":
            return "bg-yellow-300 animate-pulse-slow";
        default:
            return "bg-nb-gray-500";
    }
};

export const PeersList = ({ data }: { data: PeerStatus[] }) => {
    const { setSelected } = usePeerDetail();

    return (
        <ul className={"flex flex-col"}>
            {data.map((peer) => {
                const isConnected = peer.connStatus === "Connected";
                return (
                    <li
                        key={peer.pubKey}
                        onClick={() => setSelected(peer)}
                        className={cn(
                            "group flex items-start gap-2.5 px-7 py-3 min-w-0",
                            "hover:bg-nb-gray-900/40 transition-colors",
                            "wails-no-draggable cursor-pointer",
                        )}
                    >
                        <span
                            className={cn(
                                "h-2 w-2 rounded-full shrink-0 mt-2",
                                dotClass(peer.connStatus),
                            )}
                            title={peer.connStatus}
                        />
                        <div className={"min-w-0 flex-1 flex flex-col leading-tight"}>
                            <div>
                                <CopyToClipboard message={peer.fqdn}>
                                    <span
                                        className={
                                            "text-[0.81rem] font-medium text-nb-gray-100 truncate"
                                        }
                                    >
                                        {peer.fqdn}
                                    </span>
                                </CopyToClipboard>
                            </div>
                            <div>
                                <CopyToClipboard message={peer.ip}>
                                    <span className={"text-xs font-mono text-nb-gray-400 truncate"}>
                                        {peer.ip}
                                    </span>
                                </CopyToClipboard>
                            </div>
                        </div>
                        {isConnected && peer.latencyMs > 0 && (
                            <span
                                className={cn(
                                    "shrink-0 self-center text-xs tabular-nums",
                                    latencyColor(peer.latencyMs),
                                )}
                            >
                                {peer.latencyMs} ms
                            </span>
                        )}
                        <ChevronRightIcon
                            size={16}
                            className={cn(
                                "shrink-0 self-center text-nb-gray-300",
                                "opacity-0 group-hover:opacity-100 transition-opacity",
                            )}
                        />
                    </li>
                );
            })}
        </ul>
    );
};
