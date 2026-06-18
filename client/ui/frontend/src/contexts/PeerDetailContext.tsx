import {
    createContext,
    useCallback,
    useContext,
    useMemo,
    useRef,
    useState,
    type ReactNode,
} from "react";
import type { PeerStatus } from "@bindings/services/models.js";

type PeerDetailContextValue = {
    selected: PeerStatus | null;
    setSelected: (p: PeerStatus | null) => void;
};

const PeerDetailContext = createContext<PeerDetailContextValue | null>(null);

export const usePeerDetail = (): PeerDetailContextValue => {
    const ctx = useContext(PeerDetailContext);
    if (!ctx) {
        throw new Error("usePeerDetail must be used inside PeerDetailProvider");
    }
    return ctx;
};

export const PeerDetailProvider = ({ children }: { children: ReactNode }) => {
    const [selected, setSelectedState] = useState<PeerStatus | null>(null);
    const openerRef = useRef<HTMLElement | null>(null);

    const setSelected = useCallback((p: PeerStatus | null) => {
        if (p) {
            const active = document.activeElement;
            openerRef.current = active instanceof HTMLElement ? active : null;
        } else {
            const opener = openerRef.current;
            openerRef.current = null;
            if (opener && opener.isConnected) {
                queueMicrotask(() => opener.focus());
            }
        }
        setSelectedState(p);
    }, []);

    const value = useMemo<PeerDetailContextValue>(
        () => ({ selected, setSelected }),
        [selected, setSelected],
    );
    return <PeerDetailContext.Provider value={value}>{children}</PeerDetailContext.Provider>;
};
