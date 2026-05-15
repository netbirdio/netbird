import { useState } from "react";
import { Button } from "@/components/Button";
import { useClientVersion } from "@/modules/auto-update/ClientVersionContext";
import { cn } from "@/lib/cn";

// Shown only when management has auto-update enabled (enforced=true) and the
// daemon has not yet started the installer (installing=false). The
// download-only branch (enforced=false) routes the user to GitHub via the
// tray menu instead; the force-install branch (installing=true) takes over
// with the full-screen UpdatingOverlay.
export const UpdateAvailableBanner = () => {
    const { updateVersion, enforced, installing, triggerUpdate } = useClientVersion();
    const [dismissed, setDismissed] = useState(false);

    if (import.meta.env.DEV) return null;
    if (!updateVersion || !enforced || installing || dismissed) return null;

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
                NetBird {updateVersion} is ready to install.
            </p>
            <div className={"flex gap-2"}>
                <Button variant={"subtle"} size={"xs"} onClick={() => setDismissed(true)}>
                    Later
                </Button>
                <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                    Install now
                </Button>
            </div>
        </div>
    );
};

export default UpdateAvailableBanner;
