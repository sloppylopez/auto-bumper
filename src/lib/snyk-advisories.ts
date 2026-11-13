/**
 * Snyk Open Source public advisories (Maven + npm), fetched from the server-rendered
 * per-package pages at security.snyk.io — no API key required. Each page embeds its
 * vulnerability list in a Nuxt `__NUXT_DATA__` payload; we convert it to OSV-shaped
 * entries and cache them per coordinate under `.auto-bumper/db/snyk/<eco>/<coord>.json`.
 *
 * This source exists because Snyk discloses many vulnerabilities (with fixed versions)
 * before OSV or the GitHub advisory list ingest them. It is a supplemental source:
 * disabled by `AUTO_BUMPER_SUPPLEMENTAL=off`, cache-only under `--offline`, and any
 * per-package failure degrades to whatever is cached instead of failing the scan.
 * A failure with no cache is reported once and marks the scan incomplete.
 */
import fs from "node:fs";
import path from "node:path";
import type { AdvisoryEntry, PackageRef } from "./types.ts";
import { getOsvDbDir } from "../path.ts";
import { CACHE_TTL_MS } from "./osv-db.ts";
import { fetchWithRetry } from "./fetch-retry.ts";
import { unionAdvisory } from "./advisory-merge.ts";

export const SNYK_SUPPORTED_ECOSYSTEMS = ["Maven", "npm"] as const;
type SnykEcosystem = (typeof SNYK_SUPPORTED_ECOSYSTEMS)[number];

const SNYK_BASE = "https://security.snyk.io/package";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) auto-bumper";
const CONCURRENCY = 4;

/** Snyk severity label → CVSS-style score. Unknown labels fall back to 3.0, matching GitHub. */
const SNYK_SEVERITY_SCORE: Record<string, string> = { critical: "9.0", high: "7.5", medium: "4.0", low: "3.0" };
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** One affected-version window from a Snyk package page. */
export interface SnykVersionBound {
  version: string;
  inclusive: boolean;
}
export interface SnykVersionWindow {
  min: SnykVersionBound | null;
  max: SnykVersionBound | null;
}
/** One vulnerability entry from a Snyk package page (fields the converter needs). */
export interface SnykVuln {
  id: string;
  title?: string;
  severity?: string;
  /** Numeric CVSS from the page, when Snyk embeds one. Preferred over the label bucket. */
  cvssScore?: number | string;
  affectedVersions?: SnykVersionWindow[];
  identifiers?: { CVE?: string[]; GHSA?: string[] };
}

/** Per-coordinate cache document. */
interface SnykCacheDoc {
  fetchedAt: number;
  entries: AdvisoryEntry[];
}

/** Build the public per-package page URL for a Snyk-supported ecosystem. */
export function snykPackageUrl(ecosystem: SnykEcosystem, name: string): string {
  const coordName = ecosystem === "Maven" ? name.toLowerCase() : name;
  const coord = ecosystem === "Maven" ? coordName.replaceAll(":", "%3A") : encodeURIComponent(coordName);
  return `${SNYK_BASE}/${ecosystem === "Maven" ? "maven" : "npm"}/${coord}`;
}

/** Directory holding per-coordinate Snyk caches, under the shared OSV db dir. */
export function getSnykCacheDir(): string {
  return path.join(getOsvDbDir(), "snyk");
}

function cacheFileFor(ecosystem: SnykEcosystem, name: string): string {
  const safe = name.replace(/[^a-zA-Z0-9._@-]/g, "_");
  return path.join(getSnykCacheDir(), ecosystem.toLowerCase(), `${safe}.json`);
}

function readCache(file: string): SnykCacheDoc | null {
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8")) as SnykCacheDoc;
    if (!Array.isArray(doc.entries) || typeof doc.fetchedAt !== "number") return null;
    return doc;
  } catch {
    return null;
  }
}

function writeCache(file: string, entries: AdvisoryEntry[]): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ fetchedAt: Date.now(), entries } satisfies SnykCacheDoc));
  fs.renameSync(tmp, file);
}

// ─── Nuxt payload parsing ─────────────────────────────────────

/**
 * Extract and parse the `__NUXT_DATA__` payload of a Snyk package page.
 * The payload is a devalue-style JSON array whose elements reference each other by
 * numeric index; returns the raw node list (unresolved). Throws on malformed input.
 */
export function parseSnykPayload(html: string): unknown[] {
  const marker = "__NUXT_DATA__\">";
  const i = html.indexOf(marker);
  if (i < 0) throw new Error("no __NUXT_DATA__ payload in page");
  let s = html.slice(i + marker.length);
  const j = s.indexOf("</script>");
  if (j < 0) throw new Error("unterminated __NUXT_DATA__ payload");
  s = s.slice(0, j).trim();
  const nodes: unknown = JSON.parse(s);
  if (!Array.isArray(nodes)) throw new Error("__NUXT_DATA__ payload is not an array");
  return nodes;
}

function assignResolved(o: Record<string, unknown>, key: unknown, value: unknown): void {
  const name = String(key);
  if (DANGEROUS_KEYS.has(name)) return;
  o[name] = value;
}

/** Resolve a numeric reference into the node list, guarding cycles and out-of-range values. */
function resolveNumberRef(v: number, nodes: unknown[], nextDepth: number, anc: Set<number>): unknown {
  if (!Number.isInteger(v) || v < 0 || v >= nodes.length) return v < 0 ? null : v;
  if (anc.has(v)) return null;
  anc.add(v);
  try {
    return resolveNuxt(nodes[v], nodes, nextDepth, anc);
  } finally {
    anc.delete(v);
  }
}

/** Resolve a devalue-tagged array (`ShallowReactive`, `Reactive`, `Object`, `Array`). */
function resolveTaggedArray(tag: string, rest: unknown[], v: unknown[], nodes: unknown[], nextDepth: number, anc: Set<number>): unknown {
  if (tag === "ShallowReactive" || tag === "Reactive") return resolveNuxt(rest[0], nodes, nextDepth, anc);
  if (tag === "Object") {
    const o: Record<string, unknown> = Object.create(null);
    for (let k = 0; k < rest.length; k += 2) {
      assignResolved(o, resolveNuxt(rest[k], nodes, nextDepth, anc), resolveNuxt(rest[k + 1], nodes, nextDepth, anc));
    }
    return o;
  }
  if (tag === "Array") return rest.map((x) => resolveNuxt(x, nodes, nextDepth, anc));
  return v.map((x) => resolveNuxt(x, nodes, nextDepth, anc));
}

/** Resolve a plain object node key by key. */
function resolvePlainObject(v: object, nodes: unknown[], nextDepth: number, anc: Set<number>): Record<string, unknown> {
  const o: Record<string, unknown> = Object.create(null);
  for (const [k, val] of Object.entries(v)) assignResolved(o, k, resolveNuxt(val, nodes, nextDepth, anc));
  return o;
}

/** Resolve one devalue node (numeric values are references into the node list). */
function resolveNuxt(v: unknown, nodes: unknown[], depth: number, anc: Set<number>): unknown {
  if (depth > 64) return null;
  if (typeof v === "number") return resolveNumberRef(v, nodes, depth + 1, anc);
  if (Array.isArray(v)) {
    const [tag, ...rest] = v;
    if (typeof tag === "string") return resolveTaggedArray(tag, rest, v, nodes, depth + 1, anc);
    return v.map((x) => resolveNuxt(x, nodes, depth + 1, anc));
  }
  if (v && typeof v === "object") return resolvePlainObject(v, nodes, depth + 1, anc);
  return v;
}

function isVulnList(val: unknown[]): boolean {
  return val.every((v) => !!v && typeof v === "object" && typeof (v as SnykVuln).id === "string");
}

interface VulnWalkState {
  sawEmpty: boolean;
}

/** Recursively look for a `vulnerabilities` array in a resolved payload. */
function walkForVulnerabilities(current: unknown, depth: number, state: VulnWalkState): SnykVuln[] | null {
  if (depth > 24 || current === null || typeof current !== "object") return null;
  if (Array.isArray(current)) return searchArrayItems(current, state, depth);
  const direct = directVulnList(current as Record<string, unknown>, state);
  if (direct) return direct;
  return searchObjectValues(current as Record<string, unknown>, state, depth);
}

/** A well-formed `vulnerabilities` array directly on the node; empty ones mark `state.sawEmpty`. */
function directVulnList(current: Record<string, unknown>, state: VulnWalkState): SnykVuln[] | null {
  for (const [k, val] of Object.entries(current)) {
    if (k !== "vulnerabilities" || !Array.isArray(val) || !isVulnList(val)) continue;
    if (val.length > 0) return val as SnykVuln[];
    state.sawEmpty = true;
  }
  return null;
}

/** Search each element of an array node in order; the first non-empty hit wins. */
function searchArrayItems(current: unknown[], state: VulnWalkState, depth: number): SnykVuln[] | null {
  for (const item of current) {
    const found = walkForVulnerabilities(item, depth + 1, state);
    if (found && found.length > 0) return found;
  }
  return null;
}

/** Search the values of an object node in order; the first non-empty hit wins. */
function searchObjectValues(current: Record<string, unknown>, state: VulnWalkState, depth: number): SnykVuln[] | null {
  for (const val of Object.values(current)) {
    const found = walkForVulnerabilities(val, depth + 1, state);
    if (found && found.length > 0) return found;
  }
  return null;
}

/**
 * Find a `vulnerabilities` array in a resolved payload.
 * A non-empty well-formed list wins. An empty array means the package has no
 * advisories. Null means the key was not found (the caller must not cache that).
 */
function findVulnerabilities(node: unknown): SnykVuln[] | null {
  const state: VulnWalkState = { sawEmpty: false };
  const found = walkForVulnerabilities(node, 0, state);
  if (found && found.length > 0) return found;
  return state.sawEmpty ? [] : null;
}

/** Parse a Snyk package page into its vulnerability list. Empty array when the page has none. */
export function parseSnykPackagePage(html: string): SnykVuln[] {
  const nodes = parseSnykPayload(html);
  const root = resolveNuxt(nodes[0], nodes, 0, new Set());
  const vulns = findVulnerabilities(root);
  if (!vulns) throw new Error("no vulnerabilities array in Snyk payload");
  return vulns;
}

// ─── OSV conversion ─────────────────────────────────────

/**
 * Convert one Snyk vulnerability into an OSV-shaped entry for `pkgName` in `ecosystem`.
 * Id is the primary CVE when present, else the SNYK id; aliases carry every known id.
 * Each affected-version window becomes one ECOSYSTEM event range: an exclusive upper
 * bound is a `fixed` event, an inclusive one a `last_affected` event.
 */
export function snykVulnToOsv(vuln: SnykVuln, pkgName: string, ecosystem: SnykEcosystem): AdvisoryEntry | null {
  if (!vuln?.id) return null;
  const cves = vuln.identifiers?.CVE ?? [];
  const ghsas = vuln.identifiers?.GHSA ?? [];
  const id = cves[0] ?? vuln.id;
  const aliases = [...new Set([vuln.id, ...cves, ...ghsas])];

  const ranges: Array<{ type: string; events: Array<Record<string, string>> }> = (vuln.affectedVersions ?? []).map(
    (w) => {
      const events: Array<Record<string, string>> = [{ introduced: w.min?.version ?? "0" }];
      if (w.max?.version) {
        events.push(w.max.inclusive ? { last_affected: w.max.version } : { fixed: w.max.version });
      }
      return { type: "ECOSYSTEM", events };
    },
  );

  const score = snykScore(vuln);
  return {
    id,
    aliases,
    ecosystems: [ecosystem],
    summary: vuln.title ?? vuln.id,
    severity: [{ type: "CVSS_V3_1", score }],
    affected: [
      {
        package: { name: pkgName, ecosystem },
        ranges,
      },
    ],
    links: [
      { url: `https://security.snyk.io/vuln/${vuln.id}` },
      ...cves.map((c) => ({ url: `https://nvd.nist.gov/vuln/detail/${c}` })),
    ],
  };
}

/** Page CVSS when it is numeric; otherwise the label bucket; otherwise 3.0 (same as GitHub). */
function snykScore(vuln: SnykVuln): string {
  const raw = vuln.cvssScore;
  if (typeof raw === "number" && Number.isFinite(raw)) return String(raw);
  if (typeof raw === "string" && /^\d/.test(raw.trim())) {
    const n = Number.parseFloat(raw.trim());
    if (Number.isFinite(n)) return String(n);
  }
  return SNYK_SEVERITY_SCORE[(vuln.severity ?? "").toLowerCase()] ?? "3.0";
}

// ─── Loading ─────────────────────────────────────

export interface SnykLoadOptions {
  /** Use per-coordinate caches only; never fetch. */
  offline?: boolean;
  /** Bypass the TTL and re-fetch every coordinate. */
  forceRefresh?: boolean;
  setText?: (msg: string) => void;
  onWarning?: (msg: string) => void;
  /** A coordinate failed and nothing was cached. The scan must not report a clean result. */
  onIncomplete?: () => void;
}

interface SnykCoordinate {
  ecosystem: SnykEcosystem;
  name: string;
}

/** Canonical Snyk ecosystem for a package ecosystem (case-insensitive; parsers emit lowercase). */
function snykEcosystemFor(ecosystem: string): SnykEcosystem | null {
  const lower = ecosystem.toLowerCase();
  return (SNYK_SUPPORTED_ECOSYSTEMS as readonly string[]).find((e) => e.toLowerCase() === lower) as SnykEcosystem | undefined ?? null;
}

/** Unique Snyk-supported coordinates among scanned packages. */
function snykCoordinates(packages: PackageRef[]): SnykCoordinate[] {
  const seen = new Set<string>();
  const out: SnykCoordinate[] = [];
  for (const p of packages) {
    const eco = snykEcosystemFor(p.ecosystem);
    if (!eco) continue;
    const name = eco === "Maven" ? p.name.toLowerCase() : p.name;
    const key = `${eco}:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem: eco, name });
  }
  return out;
}

type CoordinateResult =
  | { kind: "entries"; entries: AdvisoryEntry[] }
  | { kind: "missing-cache" };

async function loadCoordinate(
  coord: SnykCoordinate,
  offline: boolean,
  forceRefresh: boolean,
): Promise<CoordinateResult> {
  const file = cacheFileFor(coord.ecosystem, coord.name);
  const cached = readCache(file);
  if (!forceRefresh && cached !== null && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return { kind: "entries", entries: cached.entries };
  }
  if (offline) {
    // Stale beats nothing; a coordinate never fetched has no data offline.
    if (cached !== null) return { kind: "entries", entries: cached.entries };
    return { kind: "missing-cache" };
  }

  try {
    const resp = await fetchWithRetry(snykPackageUrl(coord.ecosystem, coord.name), { headers: { "user-agent": USER_AGENT } }, { label: `snyk ${coord.name}` });
    if (resp.status === 404) {
      // Not in Snyk's database — cache the empty result so we do not re-probe every run.
      writeCache(file, []);
      return { kind: "entries", entries: [] };
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const html = await resp.text();
    const vulns = parseSnykPackagePage(html);
    const entries = vulns
      .map((v) => snykVulnToOsv(v, coord.name, coord.ecosystem))
      .filter((e): e is AdvisoryEntry => e !== null);
    writeCache(file, entries);
    return { kind: "entries", entries };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (cached !== null) {
      // Stale beats nothing.
      console.error(`[auto-bumper] Snyk cache for ${coord.name} is stale and refresh failed (${msg}); using cached copy`);
      return { kind: "entries", entries: cached.entries };
    }
    throw new Error(msg);
  }
}

type CoordinateOutcome = "ok" | "missing" | "failed";

/** Load one coordinate and merge its entries into the by-id map; report no-cache and fetch failures. */
async function mergeCoordinateResult(
  coord: SnykCoordinate,
  offline: boolean,
  forceRefresh: boolean,
  byId: Map<string, AdvisoryEntry>,
  failures: string[],
): Promise<CoordinateOutcome> {
  try {
    const result = await loadCoordinate(coord, offline, forceRefresh);
    if (result.kind === "missing-cache") return "missing";
    for (const e of result.entries) {
      const existing = byId.get(e.id);
      byId.set(e.id, existing ? unionAdvisory(existing, e) : e);
    }
    return "ok";
  } catch (err) {
    failures.push(`${coord.name}: ${err instanceof Error ? err.message : String(err)}`);
    return "failed";
  }
}

/**
 * Load Snyk public advisories for the scanned packages.
 * Per-coordinate caches (7-day TTL) make repeat runs cheap; a coordinate that is not in
 * Snyk's database is cached as empty. Failures fall back to stale cache where one exists;
 * when no cache exists at all the failure is reported via `onWarning` and those packages
 * simply go unmatched. That no-cache failure also calls `onIncomplete` so the
 * scan is not reported as clean. The scan itself still returns.
 */
export async function loadSnykAdvisories(packages: PackageRef[], opts: SnykLoadOptions = {}): Promise<AdvisoryEntry[]> {
  const { offline = false, forceRefresh = false, setText, onWarning, onIncomplete } = opts;
  const coords = snykCoordinates(packages);
  if (coords.length === 0) return [];

  const byId = new Map<string, AdvisoryEntry>();
  const failures: string[] = [];
  let missingOffline = 0;
  let done = 0;
  setText?.(offline ? `Loading cached Snyk advisories (0/${coords.length})...` : `Fetching Snyk advisories (0/${coords.length})...`);

  const queue = [...coords];
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, coords.length) }, async () => {
      while (queue.length > 0) {
        const coord = queue.shift()!;
        const outcome = await mergeCoordinateResult(coord, offline, forceRefresh, byId, failures);
        if (outcome === "missing") missingOffline += 1;
        done += 1;
        if (done % 10 === 0 || done === coords.length) {
          setText?.(offline ? `Loading cached Snyk advisories (${done}/${coords.length})...` : `Fetching Snyk advisories (${done}/${coords.length})...`);
        }
      }
    }),
  );

  if (missingOffline > 0) {
    onWarning?.(
      `Snyk advisories cache missing for ${missingOffline} package${missingOffline === 1 ? "" : "s"}; run a scan online once to populate it`,
    );
  }
  if (failures.length > 0) {
    onIncomplete?.();
    onWarning?.(
      `Snyk advisories unavailable for ${failures.length} of ${coords.length} packages (${failures[0]}); those packages were matched without Snyk data`,
    );
  }
  return [...byId.values()];
}
