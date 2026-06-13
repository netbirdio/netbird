import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Events } from "@wailsio/runtime";
import { Settings as SettingsSvc } from "@bindings/services";
import { Restrictions } from "@bindings/services/models.js";

const EVENT_SYSTEM = "netbird:event";
const EMPTY = new Restrictions();

const RestrictionsContext = createContext<Restrictions>(EMPTY);

export const useRestrictions = () => useContext(RestrictionsContext);

export const RestrictionsProvider = ({ children }: { children: ReactNode }) => {
    const [restrictions, setRestrictions] = useState<Restrictions>(EMPTY);

    useEffect(() => {
        let cancelled = false;

        const refresh = async () => {
            try {
                const r = await SettingsSvc.GetRestrictions();
                if (!cancelled) setRestrictions(r);
            } catch (e) {
                console.error("[RestrictionsContext] refresh failed", e);
            }
        };

        refresh();

        const off = Events.On(
            EVENT_SYSTEM,
            (e: { data?: { metadata?: { [k: string]: string | undefined } } }) => {
                if (e.data?.metadata?.type === "config_changed") refresh();
            },
        );
        return () => {
            cancelled = true;
            off();
        };
    }, []);

    return (
        <RestrictionsContext.Provider value={restrictions}>{children}</RestrictionsContext.Provider>
    );
};
