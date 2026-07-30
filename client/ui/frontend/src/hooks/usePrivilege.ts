import { useEffect, useState } from "react";
import { Settings as SettingsSvc } from "@bindings/services";
import { Privilege } from "@bindings/services/models.js";

// usePrivilege reports whether this UI process may perform the changes the daemon
// restricts to root/administrator. It is answered in-process from our own token
// with the daemon's own rule, so there is no round-trip and it works while the
// daemon is down.
//
// null means "not known yet", which includes the read having failed. Callers must
// treat that as "do not restrict": the daemon enforces this regardless, so the
// only thing a wrong guess here costs is a control that looks unavailable when it
// is not, or a save that fails with the daemon's own guidance.
export const usePrivilege = (): Privilege | null => {
    const [privilege, setPrivilege] = useState<Privilege | null>(null);

    useEffect(() => {
        let cancelled = false;
        SettingsSvc.Privilege()
            .then((p) => {
                if (!cancelled) setPrivilege(p);
            })
            .catch((e: unknown) => {
                console.warn("[usePrivilege] read failed, not restricting controls", e);
            });
        return () => {
            cancelled = true;
        };
    }, []);

    return privilege;
};
