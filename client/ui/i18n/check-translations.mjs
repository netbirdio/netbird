#!/usr/bin/env node
// Validates that every shipped translation bundle carries exactly the same set
// of keys as the English source of truth. English (en) defines the keys; every
// other locale declared in _index.json must match it 1:1:
//
//   - no missing keys — a missing key silently falls back to English at runtime
//     (see i18n bundle fallback), so the gap never surfaces to users or CI
//     without this check;
//   - no orphaned keys — keys left behind after an English key is renamed or
//     removed are dead weight and a sign the locale is drifting.
//
// Pure Node, no dependencies, so it runs without installing the frontend
// toolchain.
//
//   Local:  node client/ui/i18n/check-translations.mjs   (or: pnpm i18n:check)
//   CI:     .github/workflows/ui-translations.yml

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE = "en";
const localesDir = join(dirname(fileURLToPath(import.meta.url)), "locales");
const isCI = Boolean(process.env.GITHUB_ACTIONS);

function readJSON(path) {
    return JSON.parse(readFileSync(path, "utf8"));
}

function keysOf(langCode) {
    return Object.keys(readJSON(join(localesDir, langCode, "common.json")));
}

// Emit a GitHub Actions annotation so failures render inline on the PR diff.
function annotate(file, message) {
    if (isCI) console.log(`::error file=${file}::${message}`);
}

const index = readJSON(join(localesDir, "_index.json"));
const declared = index.languages.map((l) => l.code);

if (!declared.includes(SOURCE)) {
    console.error(`FATAL: source language "${SOURCE}" is not declared in _index.json`);
    process.exit(1);
}

const sourceKeys = keysOf(SOURCE);
const sourceSet = new Set(sourceKeys);
console.log(`Source of truth: ${SOURCE}/common.json — ${sourceKeys.length} keys\n`);

let failed = false;

for (const code of declared) {
    if (code === SOURCE) continue;
    const file = `client/ui/i18n/locales/${code}/common.json`;

    let keys;
    try {
        keys = keysOf(code);
    } catch (e) {
        failed = true;
        const msg = `bundle is declared in _index.json but common.json is missing or invalid (${e.message})`;
        console.error(`✗ ${code}: ${msg}`);
        annotate("client/ui/i18n/locales/_index.json", `${code}: ${msg}`);
        continue;
    }

    const set = new Set(keys);
    const missing = sourceKeys.filter((k) => !set.has(k));
    const extra = keys.filter((k) => !sourceSet.has(k));

    if (missing.length === 0 && extra.length === 0) {
        console.log(`✓ ${code}: ${keys.length} keys`);
        continue;
    }

    failed = true;
    console.error(`✗ ${code}: ${keys.length} keys (expected ${sourceKeys.length})`);
    if (missing.length) {
        console.error(`    missing ${missing.length}: ${missing.join(", ")}`);
        annotate(file, `Missing ${missing.length} key(s) present in ${SOURCE}: ${missing.join(", ")}`);
    }
    if (extra.length) {
        console.error(`    extra ${extra.length}: ${extra.join(", ")}`);
        annotate(file, `Has ${extra.length} key(s) not present in ${SOURCE}: ${extra.join(", ")}`);
    }
}

// Locale directories present on disk but not declared in _index.json are never
// loaded by the app — surface them so dead translation files don't rot silently.
const onDisk = readdirSync(localesDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name);
const undeclared = onDisk.filter((d) => !declared.includes(d));
if (undeclared.length) {
    console.warn(`\n⚠ locale directories not declared in _index.json (not shipped): ${undeclared.join(", ")}`);
}

console.log();
if (failed) {
    console.error("Translation check FAILED — every locale must match the English key set.");
    process.exit(1);
}
console.log("Translation check passed — all locales match the English key set.");
