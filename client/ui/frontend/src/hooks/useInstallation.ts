import { useEffect, useState } from "react";
import { Installation as InstallationSvc } from "@bindings/services";
import type { InstallationDetails } from "@bindings/services/models.js";

// The details never change while the UI runs, so every caller shares one request.
let request: Promise<InstallationDetails | null> | undefined;

function loadInstallation(): Promise<InstallationDetails | null> {
    request ??= InstallationSvc.Details().catch(() => null);
    return request;
}

// Returns the details of a named installation, or null for the default one
// and until they have loaded.
export function useInstallation(): InstallationDetails | null {
    const [details, setDetails] = useState<InstallationDetails | null>(null);
    useEffect(() => {
        let active = true;
        loadInstallation().then((d) => {
            if (active) setDetails(d?.named ? d : null);
        });
        return () => {
            active = false;
        };
    }, []);
    return details;
}
