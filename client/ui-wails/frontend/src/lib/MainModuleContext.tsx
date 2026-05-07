import { createContext, ReactNode, useContext, useState } from "react";

export type MainModule = "peers" | "settings";

type Ctx = {
    active: MainModule;
    setActive: (m: MainModule) => void;
};

const MainModuleContext = createContext<Ctx | null>(null);

export const MainModuleProvider = ({ children }: { children: ReactNode }) => {
    const [active, setActive] = useState<MainModule>("peers");
    return (
        <MainModuleContext.Provider value={{ active, setActive }}>
            {children}
        </MainModuleContext.Provider>
    );
};

export const useMainModule = () => {
    const ctx = useContext(MainModuleContext);
    if (!ctx) {
        throw new Error("useMainModule must be used within MainModuleProvider");
    }
    return ctx;
};
