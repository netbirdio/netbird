import { useCallback, useEffect, useState } from "react";
import { Preferences } from "@bindings/services";

export const useKeepConnectedOnQuit = () => {
    const [keepConnected, setKeepConnected] = useState<boolean | null>(null);

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (cancelled) return;
                setKeepConnected(prefs?.keepConnectedOnQuit ?? false);
            })
            .catch((err: unknown) => {
                if (cancelled) return;
                console.warn("[useKeepConnectedOnQuit] load preferences failed", err);
                setKeepConnected(false);
            });
        return () => {
            cancelled = true;
        };
    }, []);

    const setKeepConnectedOnQuit = useCallback(async (keep: boolean) => {
        setKeepConnected(keep);
        try {
            await Preferences.SetKeepConnectedOnQuit(keep);
        } catch (err: unknown) {
            setKeepConnected(!keep);
            console.error("[useKeepConnectedOnQuit] SetKeepConnectedOnQuit failed", err);
        }
    }, []);

    return { keepConnected, setKeepConnectedOnQuit };
};
