import { System } from "@wailsio/runtime";

export type Platform = {
  isWindows11: boolean;
  isMacOS: boolean;
  isOtherOS: boolean;
};

let cached: Platform | null = null;

// Windows 11 is Windows NT 10.0 with build number >= 22000.
function parseWindows11(version: string): boolean {
  const match = version.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return false;
  return parseInt(match[3], 10) >= 22000;
}

export async function initPlatform(): Promise<void> {
  if (cached) return;
  const isMacOS = System.IsMac();
  const isWindows = System.IsWindows();
  let isWindows11 = false;
  if (isWindows) {
    const env = await System.Environment();
    isWindows11 = parseWindows11(env.OSInfo?.Version ?? "");
  }
  cached = {
    isWindows11,
    isMacOS,
    isOtherOS: !isMacOS && !isWindows11,
  };
}

function get(): Platform {
  if (!cached) {
    throw new Error("platform: initPlatform() must complete before sync getters are used");
  }
  return cached;
}

export const getPlatform = (): Platform => get();
export const isWindows11 = (): boolean => get().isWindows11;
export const isMacOS = (): boolean => get().isMacOS;
export const isOtherOS = (): boolean => get().isOtherOS;
