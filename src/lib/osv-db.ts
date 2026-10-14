/**
 * OSV Database — ecosystem dumps via shared gzip cache (osv-cache).
 * All data stays local after initial download.
 */
import type { AdvisoryEntry } from "./types.ts";
import { getOsvDbDir } from "../path.ts";
import { LOG_PREFIX } from "./brand.ts";
import { debug } from "./debug.ts";
import { downloadOsvEcosystemDump, osvDumpUrl } from "./osv-export.ts";
import { readCacheFile, writeCacheFile, getCacheAgeMs, deleteCacheFile, writeCacheEtag } from "./osv-cache.ts";

export const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export { OSV_GCS_BASE, osvDumpUrl } from "./osv-export.ts";

/** @deprecated Prefer AdvisoryEntry[]; kept for callers that treated cache as opaque. */
export interface CachedDB {
  data: AdvisoryEntry[];
  fetchedAt: number;
  sourceUrl: string;
}

/** Default DB directory — can be overridden via env or config */
export function getDbDir(): string {
  return getOsvDbDir();
}

/**
 * Load OSV database for an ecosystem.
 * Returns cached data if fresh enough, otherwise fetches from remote.
 * Falls back to stale cache if network fails.
 */
export async function loadOSVDatabase(ecosystem: string, _dbDir?: string): Promise<AdvisoryEntry[]> {
  const age = getCacheAgeMs(ecosystem);
  if (age !== null && age < CACHE_TTL_MS) {
    const cached = readCacheFile(ecosystem);
    if (cached !== null) {
      debug(`Using cached OSV DB for ${ecosystem} (${Math.round(age / 1000 / 60)}min old)`);
      return cached;
    }
  } else if (age !== null) {
    debug(`OSV DB cache expired for ${ecosystem} (${Math.round(age / 1000 / 60 / 60)}h old), refreshing...`);
  }

  return fetchAndCacheOSV(ecosystem);
}

async function fetchAndCacheOSV(ecosystem: string): Promise<AdvisoryEntry[]> {
  debug(`Downloading OSV DB for ${ecosystem}`);

  try {
    const result = await downloadOsvEcosystemDump(ecosystem);
    debug(`Downloaded OSV DB: ${result.entries.length} entries`);
    writeCacheFile(ecosystem, result.entries);
    if (result.etag !== null) writeCacheEtag(ecosystem, result.etag);
    return result.entries;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`${LOG_PREFIX} Failed to fetch OSV DB: ${msg}`);

    const fallback = readCacheFile(ecosystem);
    if (fallback !== null) {
      debug(`Falling back to cached data for ${ecosystem}`);
      return fallback;
    }

    throw err;
  }
}

/**
 * Force update the OSV database (bypass cache TTL).
 * Used by `update-db` command / programmatic refresh.
 */
export async function updateOSVDatabase(ecosystem: string, _dbDir?: string): Promise<void> {
  deleteCacheFile(ecosystem);
  await fetchAndCacheOSV(ecosystem);
}

/**
 * Check if the OSV database exists and how old it is.
 */
export function checkDBStatus(
  ecosystem: string,
  _dbDir?: string,
): { exists: boolean; ageMs?: number; entries?: number; sourceUrl?: string } {
  const data = readCacheFile(ecosystem);
  if (data === null) return { exists: false };

  const ageMs = getCacheAgeMs(ecosystem) ?? undefined;
  return {
    exists: true,
    entries: data.length,
    ageMs,
    sourceUrl: osvDumpUrl(ecosystem),
  };
}
