// Prints the third-party terms for the prebuilt UI in dist/ to stdout.
// Package versions come from package-lock.json and the license texts from an
// installed node_modules (run `npm ci --ignore-scripts` first).
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const webDir = join(dirname(fileURLToPath(import.meta.url)), "..");

// Build tools whose own code is emitted into dist: tailwindcss generates the
// preflight and utility CSS, vite injects its modulepreload polyfill.
const bundledTooling = new Set(["node_modules/tailwindcss", "node_modules/vite"]);

// Inter ships as a font file rather than a package, so its OFL lives beside it.
const staticTerms = [
  {
    title: "Inter 4.001 (git-66647c0bb), SIL Open Font License 1.1",
    file: "src/assets/fonts/OFL.txt",
  },
];

const termPattern = /^(licen[cs]e|copying|notice|patents)/i;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function shippedPackages(lock) {
  return Object.entries(lock.packages)
    .filter(([path, meta]) => path !== "" && (!meta.dev || bundledTooling.has(path)))
    .sort(([a], [b]) => Number(a > b) - Number(a < b));
}

function packageSection(path, meta) {
  const dir = join(webDir, path);
  const manifest = join(dir, "package.json");
  if (!existsSync(manifest)) {
    fail(`${path} is not installed; run npm ci --ignore-scripts in proxy/web`);
  }
  const installed = JSON.parse(readFileSync(manifest, "utf8"));
  if (installed.version !== meta.version) {
    fail(`${path} is ${installed.version}, package-lock.json pins ${meta.version}`);
  }

  const terms = readdirSync(dir).filter((name) => termPattern.test(name)).sort();
  if (terms.length === 0) {
    fail(`no license terms found for ${path}`);
  }

  const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  return terms
    .map((term) => `=== ${name} ${meta.version} (${term}) ===\n\n${readFileSync(join(dir, term), "utf8")}`)
    .join("\n\n");
}

const lock = JSON.parse(readFileSync(join(webDir, "package-lock.json"), "utf8"));
const sections = shippedPackages(lock).map(([path, meta]) => packageSection(path, meta));
for (const { title, file } of staticTerms) {
  sections.push(`=== ${title} ===\n\n${readFileSync(join(webDir, file), "utf8")}`);
}

process.stdout.write(
  "Third-party terms for the prebuilt authentication UI in proxy/web/dist.\n" +
    "Generated from proxy/web/package-lock.json at release time.\n\n\n" +
    sections.join("\n\n\n") +
    "\n",
);
