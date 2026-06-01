import { System } from "@wailsio/runtime";

export type Platform = {
  isWindows: boolean;
  isMacOS: boolean;
};

let cached: Platform | null = null;

export async function initPlatform(): Promise<void> {
  if (cached) return;

  // Sync getters read the page-injected `window._wails.environment`, which can
  // be empty if the injection hasn't landed yet — keep them only as a fallback.
  const syncIsMac = System.IsMac();
  const syncIsWindows = System.IsWindows();

  // The async Environment() call round-trips to the Go backend and is the
  // authoritative source for OS.
  let env: Awaited<ReturnType<typeof System.Environment>> | null = null;
  try {
    env = await System.Environment();
  } catch (e) {
    console.error("[platform] System.Environment() threw:", e);
  }

  // Prefer the async env.OS; fall back to the sync getters if it's missing.
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
