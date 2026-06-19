import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useRef,
    useState,
    type ReactNode,
} from "react";
import { Events } from "@wailsio/runtime";
import { Settings as SettingsSvc } from "@bindings/services";
import { Restrictions } from "@bindings/services/models.js";
import { useStatus } from "@/contexts/StatusContext.tsx";

const EVENT_SYSTEM = "netbird:event";
const EMPTY = new Restrictions();

const RestrictionsContext = createContext<Restrictions>(EMPTY);

export const useRestrictions = () => useContext(RestrictionsContext);

export const RestrictionsProvider = ({ children }: { children: ReactNode }) => {
    const [restrictions, setRestrictions] = useState<Restrictions>(EMPTY);
    const mounted = useRef(true);
    const { status } = useStatus();

    const refresh = useCallback(async () => {
        try {
            const r = await SettingsSvc.GetRestrictions();
            if (mounted.current) setRestrictions(r);
        } catch (e) {
            console.error("[RestrictionsContext] refresh failed", e);
        }
    }, []);

    useEffect(() => {
        mounted.current = true;

        const off = Events.On(
            EVENT_SYSTEM,
            (e: { data?: { metadata?: { [k: string]: string | undefined } } }) => {
                if (e.data?.metadata?.type === "config_changed") refresh();
            },
        );

        const onVisible = () => {
            if (document.visibilityState === "visible") refresh();
        };
        document.addEventListener("visibilitychange", onVisible);

        return () => {
            mounted.current = false;
            off();
            document.removeEventListener("visibilitychange", onVisible);
        };
    }, [refresh]);

    useEffect(() => {
        if (status?.status) refresh();
    }, [status?.status, refresh]);

    return (
        <RestrictionsContext.Provider value={restrictions}>{children}</RestrictionsContext.Provider>
    );
};
