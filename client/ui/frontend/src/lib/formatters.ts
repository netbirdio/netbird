export const formatBytes = (bytes: number, decimals: number = 2): string => {
    try {
        if (bytes === 0) return "0 B";

        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return (
            parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) +
            " " +
            sizes[i]
        );
    } catch {
        return "0 B";
    }
};

export const latencyColor = (ms: number): string => {
    if (ms <= 0) return "text-nb-gray-400";
    if (ms < 100) return "text-green-400";
    return "text-yellow-400";
};

export const formatRelative = (
    unixSeconds: number,
    nowMs: number = Date.now(),
): string | null => {
    if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return null;
    const diff = Math.max(0, Math.floor(nowMs / 1000 - unixSeconds));
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
};

// shortenDns drops the domain suffix off a DNS name, returning just the
// leading host label ("misha.netbird.selfhosted" → "misha"). The base domain
// is operator-configurable so we keep everything before the first dot rather
// than matching against a known suffix. The full DNS name still lands on
// the clipboard via the copy helpers' explicit message prop.
export const shortenDns = (fqdn: string | undefined | null): string => {
    if (!fqdn) return "";
    const dot = fqdn.indexOf(".");
    return dot === -1 ? fqdn : fqdn.slice(0, dot);
};
