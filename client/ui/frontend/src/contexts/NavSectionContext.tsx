import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

export type NavSection = "peers" | "networks";

type NavSectionContextValue = {
    section: NavSection;
    setSection: (s: NavSection) => void;
};

const NavSectionContext = createContext<NavSectionContextValue | null>(null);

export const useNavSection = (): NavSectionContextValue => {
    const ctx = useContext(NavSectionContext);
    if (!ctx) {
        throw new Error("useNavSection must be used inside NavSectionProvider");
    }
    return ctx;
};

export const NavSectionProvider = ({ children }: { children: ReactNode }) => {
    const [section, setSection] = useState<NavSection>("peers");
    const value = useMemo<NavSectionContextValue>(() => ({ section, setSection }), [section]);
    return <NavSectionContext.Provider value={value}>{children}</NavSectionContext.Provider>;
};
