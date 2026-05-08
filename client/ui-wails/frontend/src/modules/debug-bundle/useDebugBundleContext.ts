import { useContext } from "react";
import { DebugBundleContext } from "@/modules/debug-bundle/DebugBundleContext.tsx";

export const useDebugBundleContext = () => {
    const ctx = useContext(DebugBundleContext);
    if (!ctx) {
        throw new Error(
            "useDebugBundleContext must be used inside DebugBundleProvider",
        );
    }
    return ctx;
};
