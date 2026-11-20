import assert from "node:assert/strict";
import { test } from "node:test";
import { overlappingRouteIds } from "./overlap.ts";

for (const [first, second, overlaps] of [
    ["172.16.0.0/16", "172.16.0.0/24", true],
    ["192.168.198.0/24", "192.168.198.0/21", true],
    ["10.0.0.0/24", "10.0.0.0/24", true],
    ["10.0.0.0/24", "10.0.1.0/24", false],
    ["10.0.0.0/24", "192.168.0.0/16", false],
    ["10.0.0.0/24", "::a00:0/120", false],
    ["10.0.0.127/25", "10.0.0.1/32", true],
    ["10.0.0.127/25", "10.0.0.128/32", false],
    ["2001:db8::1/65", "2001:db8::abcd/128", true],
    ["2001:db8::1/65", "2001:db8:0:0:8000::/128", false],
    ["2001:DB8::/64", "2001:0db8:0000:0000:0000:0000:0000:0000/64", true],
    ["::ffff:192.168.1.1/128", "0:0:0:0:0:ffff:c0a8:100/120", true],
    [" 10.0.0.0/24 , 2001:db8::/64 ", "192.168.0.0/16,2001:db8::1/128", true],
    ["10.0.0.0/24,2001:::bad/64", "10.0.0.1/32", true],
    ["invalid Prefix,,10.0.0.0/24", "10.0.0.1/32", true],
] as const) {
    test(`${first} and ${second}: overlap=${overlaps}`, () => {
        for (const selected of [false, true]) {
            const routes = [
                { id: "a", range: first, domains: [], selected },
                { id: "b", range: second, domains: [], selected: !selected },
            ];
            const expected = new Set(overlaps ? ["a", "b"] : []);
            assert.deepEqual(overlappingRouteIds(routes), expected);
            assert.deepEqual(overlappingRouteIds(routes.reverse()), expected);
        }
    });
}

test("invalid prefixes do not overlap even identical strings", () => {
    for (const range of [
        "",
        "invalid Prefix",
        "10.0.0.0",
        "10.0.0.0/",
        "10.0.0.0/-1",
        "10.0.0.0/33",
        "10.0.0.0/1.5",
        "256.0.0.0/24",
        "10.0.0/24",
        "::/129",
        "1::2::3/64",
        "1:2:3/64",
        "1:2:3:4:5:6:7:8:9/64",
        "1:2:3:4:5:6:7::8/64",
        "gggg::/64",
        "::ffff:999.0.0.1/128",
        "192.168.1.1::/64",
        "::1/64/64",
    ]) {
        assert.deepEqual(
            overlappingRouteIds([
                { id: "a", range, domains: [] },
                { id: "b", range, domains: [] },
            ]),
            new Set(),
            range,
        );
    }
});

test("only distinct non-domain routes contribute IDs", () => {
    assert.deepEqual(overlappingRouteIds([]), new Set());
    assert.deepEqual(
        overlappingRouteIds([
            { id: "a", range: "10.0.0.0/16,10.0.0.0/24,10.0.0.0/24", domains: [] },
        ]),
        new Set(),
    );
    assert.deepEqual(
        overlappingRouteIds([
            { id: "a", range: "10.0.0.0/24", domains: ["a.example"] },
            { id: "b", range: "10.0.0.0/24", domains: ["b.example"] },
        ]),
        new Set(),
    );
});

test("a broad route overlaps two disjoint routes without grouping them", () => {
    const routes = [
        { id: "broad", range: "10.0.0.0/16", domains: [] },
        { id: "a", range: "10.0.1.0/24", domains: [] },
        { id: "b", range: "10.0.2.0/24", domains: [] },
    ];
    assert.deepEqual(overlappingRouteIds(routes), new Set(["broad", "a", "b"]));
    assert.deepEqual(overlappingRouteIds(routes.slice(1)), new Set());
});
