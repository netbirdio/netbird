import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
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
    const [selected, setSelected] = useState<PeerStatus | null>(null);
    const value = useMemo<PeerDetailContextValue>(() => ({ selected, setSelected }), [selected]);
    return <PeerDetailContext.Provider value={value}>{children}</PeerDetailContext.Provider>;
};
