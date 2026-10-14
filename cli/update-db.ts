#!/usr/bin/env bun
/**
 * Auto-Bumper DB Update — Fetch latest OSV vulnerability database.
 *
 * Usage:
 *   update-db [--ecosystem=Maven]
 *   bun cli/update-db.ts [options]   (local dev)
 */
import { createSpinner } from "../src/lib/spinner.ts";
import { getOsvDbDir } from "../src/path.ts";
import { PRODUCT_NAME } from "../src/lib/brand.ts";
import { ECOSYSTEM_OSV_NAME } from "../src/lib/parse-lockfile.ts";
import { loadAdvisoriesForEcosystem } from "../src/scan.ts";

const DB_DIR = getOsvDbDir();
const DEFAULT_OSV_NAMES = ["NPM", "CRATES.IO", "PyPI", "Maven"];

const args = process.argv.slice(2);
const ecosystemFlag = args.find(a => a.startsWith("--ecosystem"));
const osvNames = ecosystemFlag ? [ecosystemFlag.split("=")[1]!] : DEFAULT_OSV_NAMES;

const internalKeyForOsvName = (osvName: string): string => {
  const entry = Object.entries(ECOSYSTEM_OSV_NAME).find(([, v]) => v.toLowerCase() === osvName.toLowerCase());
  return entry?.[0] || osvName.toLowerCase();
};

console.log(`${PRODUCT_NAME} DB Updater`);
console.log(`Target directory: ${DB_DIR}`);
console.log(`Ecosystems: ${osvNames.join(", ")}`);
console.log();

let totalEntries = 0;

for (const osvName of osvNames) {
  const spinner = createSpinner(`Fetching ${osvName}...`).start();
  try {
    const advs = await loadAdvisoriesForEcosystem(internalKeyForOsvName(osvName), spinner);
    totalEntries += advs.length;
    spinner.succeed(`${osvName}: ${advs.length} entries cached`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    spinner.fail(`${osvName}: ${msg}`);
  }
}

console.log(`\nDone. Total entries: ${totalEntries}`);
