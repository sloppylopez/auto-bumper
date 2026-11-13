/**
 * Discover and cache package-less OSV CVEs for bridged Maven products.
 * Maven/all.zip misses these; we pull CVE IDs from vendor security
 * pages, fetch OSV records, and synthesize Maven package bindings.
 */
import type { AdvisoryEntry, PackageRef } from "./types.ts";
import {
  BRIDGE_PRODUCTS,
  bridgeProductsForPackages,
  packagesNeedOrphanBridge,
  type BridgeProduct,
} from "./osv-package-bridge.ts";
import { mapOsvVulnToAdvisory } from "./osv-export.ts";
import { CACHE_TTL_MS } from "./osv-db.ts";
import { readCacheFile, writeCacheFile, getCacheAgeMs, deleteCacheFile } from "./osv-cache.ts";
import crypto from "node:crypto";

const LEGACY_ORPHAN_CACHE_NAME = "Maven-orphan";

/** Content-keyed cache name: changes when bridged products or their CVE lists change. */
export function orphanCacheName(products: BridgeProduct[]): string {
  const fingerprint = products
    .map(p => `${p.id}|${(p.knownCveIds ?? []).join(",")}|${p.advisoryIdSources.join(",")}`)
    .sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    })
    .join("\u00a7");
  return `Maven-orphan-${crypto.createHash("sha256").update(fingerprint).digest("hex").slice(0, 12)}`;
}

const ORPHAN_CACHE_NAME = orphanCacheName(BRIDGE_PRODUCTS);
const CVE_ID_RE = /CVE-\d{4}-\d+/gi;

export function extractCveIdsFromHtml(html: string): string[] {
  const ids = new Set<string>();
  for (const m of html.matchAll(CVE_ID_RE)) {
    ids.add(m[0]!.toUpperCase());
  }
  return [...ids];
}

async function fetchCveIdsFromSources(product: BridgeProduct): Promise<string[]> {
  const ids = new Set<string>();
  for (const url of product.advisoryIdSources) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) continue;
      for (const id of extractCveIdsFromHtml(await resp.text())) ids.add(id);
    } catch {
      // ignore source failures; other sources / cache may still help
    }
  }
  return [...ids];
}

async function fetchOsvVuln(id: string): Promise<Record<string, unknown> | null> {
  try {
    const resp = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
    if (!resp.ok) return null;
    return (await resp.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function isBridgedMavenAdvisory(entry: AdvisoryEntry): boolean {
  if (!entry.ecosystems.some(e => e.toLowerCase() === "maven")) return false;
  return entry.affected.some(a => Boolean(a.package?.name?.trim()));
}

/** Fetch + bridge orphan CVEs for the given products. */
export async function fetchOrphanBridgedAdvisories(
  products: BridgeProduct[] = BRIDGE_PRODUCTS,
): Promise<AdvisoryEntry[]> {
  const idSet = new Set<string>();
  for (const product of products) {
    for (const id of product.knownCveIds ?? []) idSet.add(id);
    for (const id of await fetchCveIdsFromSources(product)) idSet.add(id);
  }

  const advisories: AdvisoryEntry[] = [];
  for (const id of idSet) {
    const raw = await fetchOsvVuln(id);
    if (!raw) continue;
    const entry = mapOsvVulnToAdvisory(raw);
    if (isBridgedMavenAdvisory(entry)) advisories.push(entry);
  }
  return advisories;
}

export interface OrphanLoadOptions {
  offline?: boolean;
  /** Bypass TTL and re-fetch */
  forceRefresh?: boolean;
}

/**
 * Load bridged orphan Maven advisories for packages in the scan set.
 * Uses a content-keyed local cache (Maven-orphan-<hash>) with the same TTL as
 * ecosystem dumps; the key changes when BRIDGE_PRODUCTS changes so a stale
 * product set is never served from an old cache file.
 */
export async function loadOrphanBridgedAdvisories(
  packages: PackageRef[],
  opts: OrphanLoadOptions = {},
): Promise<AdvisoryEntry[]> {
  deleteCacheFile(LEGACY_ORPHAN_CACHE_NAME); // one-time cutover from the unkeyed name
  const products = bridgeProductsForPackages(packages);
  if (products.length === 0 && !opts.forceRefresh) return [];
  if (!opts.forceRefresh && !packagesNeedOrphanBridge(packages)) return [];

  const cached = readCacheFile(ORPHAN_CACHE_NAME);
  const age = getCacheAgeMs(ORPHAN_CACHE_NAME);
  const fresh = cached !== null && age !== null && age < CACHE_TTL_MS;

  if (opts.offline) return cached ?? [];
  if (fresh && !opts.forceRefresh) return cached!;

  try {
    // Always fetch the full product set so cache contents match the content key,
    // regardless of which bridged packages this particular scan contains.
    const fetched = await fetchOrphanBridgedAdvisories(BRIDGE_PRODUCTS);
    if (fetched.length > 0) {
      writeCacheFile(ORPHAN_CACHE_NAME, fetched);
      return fetched;
    }
    return cached ?? [];
  } catch {
    return cached ?? [];
  }
}

/** Refresh orphan bridge cache (used by update-db for Maven). */
export async function refreshOrphanBridgedAdvisories(): Promise<AdvisoryEntry[]> {
  deleteCacheFile(LEGACY_ORPHAN_CACHE_NAME); // one-time cutover from the unkeyed name
  const fetched = await fetchOrphanBridgedAdvisories(BRIDGE_PRODUCTS);
  if (fetched.length > 0) writeCacheFile(ORPHAN_CACHE_NAME, fetched);
  return fetched;
}
