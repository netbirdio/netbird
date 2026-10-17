import { useEffect, useState } from "react";
import { Version } from "@bindings/services";

const UNKNOWN_VERSION = "—";

// useGuiVersion reports the UI binary's own version, which is stamped into it at
// build time and answered in-process. The daemon version comes from the status
// feed instead, see StatusContext.
export const useGuiVersion = (): string => {
    const [guiVersion, setGuiVersion] = useState<string>(UNKNOWN_VERSION);

    useEffect(() => {
        let cancelled = false;
        Version.GUI()
            .then((v) => {
                if (!cancelled) setGuiVersion(v);
            })
            .catch((e: unknown) => {
                console.warn("[useGuiVersion] read failed", e);
            });
        return () => {
            cancelled = true;
        };
    }, []);

    return guiVersion;
};
