import { Compat } from "@bindings/services";

let cached: boolean | null = null;

/**
 * isDaemonCompatible probes whether the running daemon implements the WailsUIReady
 * RPC. A false result means the daemon predates this UI (Unimplemented) and is too
 * old to drive it. The Go side returns an error instead when the daemon is simply
 * unreachable, so a throw here is NOT an outdated daemon — treat it as "unknown"
 * and let the normal connection flow report it.
 *
 * The result is cached for the session: daemon identity does not change without a
 * UI restart, and a freshly started daemon is reachable again under the same socket.
 */
export async function isDaemonCompatible(): Promise<boolean> {
    if (cached !== null) return cached;
    cached = await Compat.DaemonReady();
    return cached;
}
