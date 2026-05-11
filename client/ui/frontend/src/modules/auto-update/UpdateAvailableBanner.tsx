import { useState } from "react";
import { Button } from "@/components/Button";
import { useClientVersion } from "@/modules/auto-update/ClientVersionContext";
import { cn } from "@/lib/cn";

// TODO: Shown only when management has auto updates enabled + there are updates available + force updates is disabled
export const UpdateAvailableBanner = () => {
    const { updateVersion, triggerUpdate } = useClientVersion();
    const [dismissed, setDismissed] = useState(false);

    if (import.meta.env.DEV) return null;
    if (!updateVersion || dismissed) return null;

    return (
        <div
            className={cn(
                "absolute bottom-4 left-1/2 -translate-x-1/2 z-50",
                "w-[calc(100%-2rem)] max-w-xl",
                "flex items-center justify-between gap-3",
                "rounded-xl border border-nb-gray-800 bg-white backdrop-blur",
                "px-2 py-2 shadow-lg",
            )}
        >
            <p className={"text-sm text-nb-gray-900 pr-4 pl-2 font-medium"}>
                NetBird will update when you restart the app.
            </p>
            <div className={"flex gap-2"}>
                <Button variant={"subtle"} size={"xs"} onClick={() => setDismissed(true)}>
                    Later
                </Button>
                <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                    Restart now
                </Button>
            </div>
        </div>
    );
};

export default UpdateAvailableBanner;
