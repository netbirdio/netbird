import { createContext, type ReactNode } from "react";
import { useDebugBundle } from "@/modules/debug-bundle/useDebugBundle.ts";

export type DebugBundleContextValue = ReturnType<typeof useDebugBundle>;

export const DebugBundleContext =
    createContext<DebugBundleContextValue | null>(null);

export const DebugBundleProvider = ({ children }: { children: ReactNode }) => {
    const value = useDebugBundle();
    return (
        <DebugBundleContext.Provider value={value}>
            {children}
        </DebugBundleContext.Provider>
    );
};
