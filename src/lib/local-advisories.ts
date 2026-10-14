/**
 * Locally-vendored advisories (OSV format) for disclosures not yet present in the
 * bulk OSV dumps — e.g. vendor-published CVEs that Snyk/NVD disclosed before OSV ingested them.
 * Files: <packageRoot>/local-advisories/*.json — each a JSON array of OSV entries.
 * Always loaded from disk; never fetched from any network source.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AdvisoryEntry } from "./types.ts";
import { LOG_PREFIX } from "./brand.ts";

/** Directory holding vendored advisory files, anchored to the package root (cwd-independent). */
export function getLocalAdvisoriesDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "local-advisories");
}

/**
 * Load all locally-vendored advisories. Malformed files are skipped with a warning;
 * a missing directory yields an empty list.
 */
export function loadLocalAdvisories(dir: string = getLocalAdvisoriesDir()): AdvisoryEntry[] {
  if (!fs.existsSync(dir)) return [];

  const out: AdvisoryEntry[] = [];
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort((a, b) => a.localeCompare(b))) {
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
      const entries = Array.isArray(raw) ? raw : [raw];
      out.push(...(entries as AdvisoryEntry[]));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${LOG_PREFIX} Skipping malformed local advisory file ${file}: ${msg}`);
    }
  }
  return out;
}
