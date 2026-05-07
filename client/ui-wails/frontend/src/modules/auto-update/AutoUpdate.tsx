import { useState } from "react";
import { Button } from "@/components/Button";
import { useStatus } from "@/hooks/useStatus";
import { Update as UpdateSvc } from "@bindings/services";

export const AutoUpdate = () => {
    const { status } = useStatus();
    const [dismissed, setDismissed] = useState(false);

    if (import.meta.env.DEV) return null;

    const updateVersion = (status?.events ?? [])
        .map((e) => e.metadata?.["new_version_available"])
        .find((v): v is string => Boolean(v));

    if (!updateVersion || dismissed) return null;

    const triggerUpdate = () => {
        UpdateSvc.Trigger().catch(() => {});
    };

    return (
        <div
            className={
                "absolute bottom-4 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 rounded-lg border border-nb-gray-800 bg-nb-gray-920/95 backdrop-blur px-4 py-2.5 shadow-lg"
            }
        >
            <p className={"text-sm text-nb-gray-100 pr-2"}>
                NetBird will update when you restart the app.
            </p>
            <Button
                variant={"secondary"}
                size={"xs"}
                onClick={() => setDismissed(true)}
            >
                Later
            </Button>
            <Button variant={"primary"} size={"xs"} onClick={triggerUpdate}>
                Restart now
            </Button>
        </div>
    );
};

export default AutoUpdate;
