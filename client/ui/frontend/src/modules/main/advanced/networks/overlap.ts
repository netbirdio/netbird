type Prefix = {
    bytes: number[];
    bits: number;
};

const parseIPv4 = (address: string): number[] | undefined => {
    const parts = address.split(".");
    if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part))) {
        return undefined;
    }
    const bytes = parts.map(Number);
    return bytes.every((byte) => byte <= 255) ? bytes : undefined;
};

const parseIPv6 = (address: string): number[] | undefined => {
    if (address.includes(".")) {
        const tailStart = address.lastIndexOf(":") + 1;
        const tail = parseIPv4(address.slice(tailStart));
        if (!tail || tailStart === 0) return undefined;
        address = `${address.slice(0, tailStart)}${((tail[0] << 8) | tail[1]).toString(16)}:${((tail[2] << 8) | tail[3]).toString(16)}`;
    }
    const halves = address.split("::");
    if (halves.length > 2) return undefined;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    const groups = [...left, ...right];
    if (groups.some((group) => !/^[\da-f]{1,4}$/i.test(group))) return undefined;
    const missing = 8 - groups.length;
    if (halves.length === 2 ? missing < 1 : missing !== 0) return undefined;
    const expanded = [...left, ...Array<string>(missing).fill("0"), ...right];
    return expanded.flatMap((group) => {
        const value = parseInt(group, 16);
        return [value >> 8, value & 255];
    });
};

const parsePrefix = (cidr: string): Prefix | undefined => {
    const parts = cidr.trim().split("/");
    if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) return undefined;
    const bytes = parts[0].includes(":") ? parseIPv6(parts[0]) : parseIPv4(parts[0]);
    const bits = Number(parts[1]);
    if (!bytes || bits > bytes.length * 8) return undefined;
    return { bytes, bits };
};

const prefixesOverlap = (a: Prefix, b: Prefix): boolean => {
    if (a.bytes.length !== b.bytes.length) return false;
    const bits = Math.min(a.bits, b.bits);
    for (let i = 0; i < Math.ceil(bits / 8); i++) {
        const mask = (255 << Math.max(0, 8 - (bits - i * 8))) & 255;
        if ((a.bytes[i] & mask) !== (b.bytes[i] & mask)) return false;
    }
    return true;
};

// overlappingRouteIds returns IDs of non-domain routes sharing any address with another route.
export const overlappingRouteIds = (
    routes: { id: string; range: string; domains: string[] }[],
): Set<string> => {
    const parsed = routes
        .filter((route) => route.domains.length === 0)
        .map((route) => ({
            id: route.id,
            prefixes: route.range
                .split(",")
                .map(parsePrefix)
                .filter((prefix): prefix is Prefix => prefix !== undefined),
        }));
    const ids = new Set<string>();
    for (let i = 0; i < parsed.length; i++) {
        for (let j = i + 1; j < parsed.length; j++) {
            const a = parsed[i];
            const b = parsed[j];
            if (a.id === b.id) continue;
            if (
                a.prefixes.some((first) =>
                    b.prefixes.some((second) => prefixesOverlap(first, second)),
                )
            ) {
                ids.add(a.id);
                ids.add(b.id);
            }
        }
    }
    return ids;
};
