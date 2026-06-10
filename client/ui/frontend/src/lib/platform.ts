import { System } from "@wailsio/runtime";

export type Platform = {
    isWindows: boolean;
    isMacOS: boolean;
};

let cached: Platform | null = null;

export async function initPlatform(): Promise<void> {
    if (cached) return;

    const syncIsMac = System.IsMac();
    const syncIsWindows = System.IsWindows();

    let env: Awaited<ReturnType<typeof System.Environment>> | null = null;
    try {
        env = await System.Environment();
    } catch (e) {
        console.error("[platform] System.Environment() threw:", e);
    }

    const os = (env?.OS ?? "").toLowerCase();
    cached = {
        isWindows: os ? os === "windows" : syncIsWindows,
        isMacOS: os ? os === "darwin" : syncIsMac,
    };
}

function get(): Platform {
    if (!cached) {
        throw new Error("platform: initPlatform() must complete before sync getters are used");
    }
    return cached;
}

export const isWindows = (): boolean => get().isWindows;
export const isMacOS = (): boolean => get().isMacOS;
export const isLinux = (): boolean => !get().isWindows && !get().isMacOS;
