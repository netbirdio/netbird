// Stable, order-preserving reconciliation for lists that re-fetch from the daemon
// on every status push (peers, networks, profiles). Re-sorting on each refresh would
// make rows jump around under the user, so instead:
//   - items already on screen keep their existing order (from `prev`),
//   - items that vanished are dropped,
//   - newly-arrived items are sorted among themselves (`compareFresh`) and appended.
// Net effect: the only visible movement is new rows landing at the bottom.
//
// Must stay pure and idempotent: callers write the returned `order` into a ref
// during render (useMemo), so a rerun must reproduce the first pass — never
// branch on run count or read external mutable state.
export function reconcileOrder<T>(
    prev: string[],
    items: T[],
    keyOf: (item: T) => string,
    compareFresh: (a: T, b: T) => number,
): { order: string[]; items: T[] } {
    const byKey = new Map(items.map((i) => [keyOf(i), i]));
    const kept = prev.filter((k) => byKey.has(k));
    const known = new Set(kept);
    const fresh = items
        .filter((i) => !known.has(keyOf(i)))
        .sort(compareFresh)
        .map(keyOf);
    const order = [...kept, ...fresh];
    return { order, items: order.map((k) => byKey.get(k)!) };
}
