#!/usr/bin/env node
// Validates every shipped translation bundle against the English source of
// truth. English (en) defines the keys; for every other locale declared in
// _index.json:
//
//   - missing keys are reported as a warning, not a failure — a missing key
//     falls back to English at runtime (see i18n bundle fallback), and Crowdin
//     exports only translated strings (skip_untranslated_strings in
//     crowdin.yml), so a locale is routinely behind English until translators
//     catch up;
//   - orphaned keys fail — keys left behind after an English key is renamed or
//     removed are dead weight and a sign the locale is drifting;
//   - empty messages fail — a present key with an empty, whitespace-only or
//     missing message renders blank instead of falling back to English;
//   - placeholder mismatches fail — a translation must use exactly the
//     {placeholders} of its English string, otherwise a value silently never
//     renders (or a literal "{name}" leaks into the UI).
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

// Matches the i18next interpolation configured in the frontend
// (prefix "{", suffix "}") and the Go bundle's applyPlaceholders.
const PLACEHOLDER = /\{([^{}\s]+)\}/g;

function readJSON(path) {
    return JSON.parse(readFileSync(path, "utf8"));
}

function messagesOf(langCode) {
    const entries = readJSON(join(localesDir, langCode, "common.json"));
    const messages = new Map();
    for (const [key, entry] of Object.entries(entries)) {
        // null marks an unusable entry (missing or non-string message).
        messages.set(key, typeof entry?.message === "string" ? entry.message : null);
    }
    return messages;
}

function placeholdersOf(message) {
    // Code-point order: placeholder names are identifiers, not prose.
    return [...new Set([...message.matchAll(PLACEHOLDER)].map((m) => m[1]))].sort((a, b) => {
        if (a < b) return -1;
        if (a > b) return 1;
        return 0;
    });
}

function formatPlaceholders(names) {
    return names.length ? names.map((n) => `{${n}}`).join(", ") : "none";
}

// Emit a GitHub Actions annotation so findings render inline on the PR diff.
function annotate(level, file, message) {
    if (isCI) console.log(`::${level} file=${file}::${message}`);
}

const index = readJSON(join(localesDir, "_index.json"));
const declared = index.languages.map((l) => l.code);

if (!declared.includes(SOURCE)) {
    console.error(`FATAL: source language "${SOURCE}" is not declared in _index.json`);
    process.exit(1);
}

const source = messagesOf(SOURCE);
const sourceKeys = [...source.keys()];
const emptySource = sourceKeys.filter((k) => !source.get(k)?.trim());
if (emptySource.length) {
    console.error(`FATAL: ${SOURCE}/common.json has empty or missing messages: ${emptySource.join(", ")}`);
    process.exit(1);
}
console.log(`Source of truth: ${SOURCE}/common.json — ${sourceKeys.length} keys\n`);

let failed = false;

for (const code of declared) {
    if (code === SOURCE) continue;
    const file = `client/ui/i18n/locales/${code}/common.json`;

    let messages;
    try {
        messages = messagesOf(code);
    } catch (e) {
        failed = true;
        const msg = `bundle is declared in _index.json but common.json is missing or invalid (${e.message})`;
        console.error(`✗ ${code}: ${msg}`);
        annotate("error", "client/ui/i18n/locales/_index.json", `${code}: ${msg}`);
        continue;
    }

    const missing = sourceKeys.filter((k) => !messages.has(k));
    const extra = [...messages.keys()].filter((k) => !source.has(k));
    const empty = [];
    const badPlaceholders = [];
    for (const [key, message] of messages) {
        if (!source.has(key)) continue;
        if (!message?.trim()) {
            empty.push(key);
            continue;
        }
        const want = placeholdersOf(source.get(key));
        const got = placeholdersOf(message);
        if (want.length !== got.length || want.some((name, i) => name !== got[i])) {
            badPlaceholders.push(`${key} (expected ${formatPlaceholders(want)}, got ${formatPlaceholders(got)})`);
        }
    }

    const translated = sourceKeys.length - missing.length - empty.length;
    const coverage = Math.floor((translated / sourceKeys.length) * 100);
    const hasErrors = extra.length > 0 || empty.length > 0 || badPlaceholders.length > 0;
    let mark = "✓";
    if (hasErrors) mark = "✗";
    else if (missing.length) mark = "⚠";
    const log = hasErrors ? console.error : console.log;
    log(`${mark} ${code}: ${translated}/${sourceKeys.length} keys translated (${coverage}%)`);

    if (missing.length) {
        console.warn(`    missing ${missing.length} (falls back to English): ${missing.join(", ")}`);
        annotate("warning", file, `Missing ${missing.length} key(s) present in ${SOURCE}, shown in English: ${missing.join(", ")}`);
    }
    if (extra.length) {
        failed = true;
        console.error(`    extra ${extra.length}: ${extra.join(", ")}`);
        annotate("error", file, `Has ${extra.length} key(s) not present in ${SOURCE}: ${extra.join(", ")}`);
    }
    if (empty.length) {
        failed = true;
        console.error(`    empty message ${empty.length} (renders blank): ${empty.join(", ")}`);
        annotate("error", file, `Empty or missing message in ${empty.length} key(s), renders blank: ${empty.join(", ")}`);
    }
    if (badPlaceholders.length) {
        failed = true;
        console.error(`    placeholder mismatch ${badPlaceholders.length}: ${badPlaceholders.join("; ")}`);
        annotate("error", file, `Placeholders differ from ${SOURCE} in ${badPlaceholders.length} key(s): ${badPlaceholders.join("; ")}`);
    }
}

// Locale directories present on disk but not declared in _index.json are not
// offered in the language picker — surface them so dead translation files don't
// rot silently.
const onDisk = readdirSync(localesDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name);
const undeclared = onDisk.filter((d) => !declared.includes(d));
if (undeclared.length) {
    console.warn(`\n⚠ locale directories not declared in _index.json (not shipped): ${undeclared.join(", ")}`);
}

console.log();
if (failed) {
    console.error("Translation check FAILED — fix orphaned keys, empty messages and placeholder mismatches above.");
    process.exit(1);
}
console.log("Translation check passed — no orphaned keys, empty messages or placeholder mismatches.");
