export const formatBytes = (bytes: number, decimals: number = 2): string => {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";

    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));

    return Number.parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + " " + sizes[i];
};

export const latencyColor = (ms: number): string => {
    if (ms <= 0) return "text-nb-gray-400";
    if (ms < 100) return "text-green-400";
    return "text-yellow-400";
};

export const formatRelative = (unixSeconds: number, nowMs: number = Date.now()): string | null => {
    if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return null;
    const diff = Math.max(0, Math.floor(nowMs / 1000 - unixSeconds));
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
};

// Base domain is operator-configurable, so cut at the first dot rather than match a known suffix.
export const shortenDns = (fqdn: string | undefined | null): string => {
    if (!fqdn) return "";
    const dot = fqdn.indexOf(".");
    return dot === -1 ? fqdn : fqdn.slice(0, dot);
};

// Countdown clock: mm:ss, widening to hh:mm:ss / dd:hh:mm:ss as the duration grows.
export const formatRemaining = (seconds: number): string => {
    const s = Math.max(0, Math.trunc(seconds));
    const days = Math.floor(s / 86400);
    const hours = Math.floor((s % 86400) / 3600);
    const minutes = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    const pad = (n: number) => String(n).padStart(2, "0");
    if (days > 0) return `${pad(days)}:${pad(hours)}:${pad(minutes)}:${pad(secs)}`;
    if (hours > 0) return `${pad(hours)}:${pad(minutes)}:${pad(secs)}`;
    return `${pad(minutes)}:${pad(secs)}`;
};
