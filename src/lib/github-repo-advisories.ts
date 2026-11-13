/**
 * GitHub global security advisories for Maven.
 *
 * OSV's Maven dump lags, and it drops rows that have no package coordinate.
 * GitHub's reviewed Maven advisories already carry group:artifact and a
 * version range. We mirror that list locally and later ask only for rows
 * updated since the last successful sync. The request never includes the
 * packages from the project being scanned.
 *
 * Unreviewed advisories are skipped: they are mostly raw NVD imports and
 * their Maven bindings are often wrong. `local-advisories/` still covers a
 * disclosure GitHub has not reviewed yet.
 */
import fs from "node:fs";
import path from "node:path";
import type { AdvisoryEntry } from "./types.ts";
import { compareMavenVersion } from "./matcher.ts";
import { CACHE_TTL_MS } from "./osv-db.ts";
import { readCacheFile, writeCacheFile, getCacheAgeMs } from "./osv-cache.ts";
import { getOsvDbDir } from "../path.ts";
import { fetchWithRetry } from "./fetch-retry.ts";

const GHSA_REPO_CACHE = "repo-advisories";
const GHSA_API = "https://api.github.com/advisories";
const GHSA_API_VERSION = "2026-03-10";
const SINCE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** UTC timestamp GitHub's `updated` filter accepts (`>=` range, no milliseconds). */
export function formatGhsaSince(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function getGhsaSincePath(): string {
  return path.join(getOsvDbDir(), `${GHSA_REPO_CACHE}.since`);
}

/** Cursor of the last successful sync, or null when a full Maven pull is required. */
export function readGhsaSince(): string | null {
  try {
    const value = fs.readFileSync(getGhsaSincePath(), "utf8").trim();
    return SINCE_RE.test(value) ? value : null;
  } catch {
    return null;
  }
}

function writeGhsaSince(value: string): void {
  const file = getGhsaSincePath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
}

/**
 * Global Maven advisory query. `since` limits the pull to advisories updated
 * at or after that UTC timestamp. `withdrawn` lists only withdrawn rows so a
 * later sync can drop them. Never sets `affects` (that parameter is a package list).
 */
export function globalMavenAdvisoriesUrl(since: string | null, withdrawn = false): string {
  const params = new URLSearchParams({
    ecosystem: "maven",
    type: "reviewed",
    per_page: "100",
    sort: "updated",
    direction: "asc",
  });
  if (withdrawn) params.set("is_withdrawn", "true");
  if (since) params.set("updated", `>=${since}`);
  return `${GHSA_API}?${params.toString()}`;
}

/**
 * Merge a sync page into the cached set. Incoming ids replace cached ones.
 * Withdrawn ids are removed even when the page also carries a body for them.
 */
export function mergeGhsaAdvisories(
  existing: AdvisoryEntry[],
  incoming: AdvisoryEntry[],
  withdrawnIds: ReadonlySet<string>,
): AdvisoryEntry[] {
  const byId = new Map<string, AdvisoryEntry>();
  for (const entry of existing) {
    if (entry.id && !withdrawnIds.has(entry.id)) byId.set(entry.id, entry);
  }
  for (const entry of incoming) {
    if (!entry.id || withdrawnIds.has(entry.id)) continue;
    byId.set(entry.id, entry);
  }
  return [...byId.values()];
}

/** Parse a GHSA vulnerable_version_range, including strict upper bounds such as "< B". */
export function parseGhsaRange(rangeStr: string | null | undefined): { exact?: string; gte?: string; gt?: string; lte?: string; lt?: string } | null {
  if (!rangeStr || typeof rangeStr !== "string") return null;
  let gte: string | undefined;
  let gt: string | undefined;
  let lte: string | undefined;
  let lt: string | undefined;
  let exact: string | undefined;
  for (const part of rangeStr.split(",").map(s => s.trim()).filter(Boolean)) {
    const opMatch = /^(>=|<=|>|<|=)/.exec(part);
    let op: string;
    let val: string;
    if (opMatch) {
      op = opMatch[1];
      val = part.slice(opMatch[0].length).trim();
    } else {
      op = "=";
      val = part;
    }
    if (!val) continue;
    if (op === ">=") gte = val;
    else if (op === ">") gt = val;
    else if (op === "<=") lte = val;
    else if (op === "<") lt = val;
    else exact = val;
  }
  if (exact !== undefined) return { exact };
  if (gte !== undefined || gt !== undefined || lte !== undefined || lt !== undefined) {
    return {
      ...(gte !== undefined ? { gte } : {}),
      ...(gt !== undefined ? { gt } : {}),
      ...(lte !== undefined ? { lte } : {}),
      ...(lt !== undefined ? { lt } : {}),
    };
  }
  return null;
}

const GHSA_SEVERITY_SCORE: Record<string, string> = { critical: "9.0", high: "7.5", medium: "4.0", low: "3.0" };

function firstPatchedVersion(raw: string | null | undefined, lte?: string): string | null {
  if (!raw || typeof raw !== "string") return null;
  for (const v of raw.split(",").map(s => s.trim()).filter(Boolean)) {
    // Vendor patched_versions are unreliable (e.g. "fixed:2.8.11" on a >= 2.17.0 range);
    // for Maven only accept a version strictly after the inclusive upper bound.
    if (lte !== undefined && compareMavenVersion(v, lte) <= 0) continue;
    return v;
  }
  return null;
}

/** GitHub advisory payload (repo endpoint and global advisory endpoint). */
export interface GhsaApiAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  severity?: string;
  summary?: string;
  html_url?: string;
  withdrawn_at?: string | null;
  cvss_severities?: { cvss_v3?: { score?: number | null } | null } | null;
  vulnerabilities?: Array<{
    package?: { name?: string; ecosystem?: string };
    vulnerable_version_range?: string;
    /** Repo security-advisories endpoint. */
    patched_versions?: string | null;
    /** Global /advisories endpoint. */
    first_patched_version?: string | null;
  }>;
}

/** One vulnerability element of a GitHub advisory. */
type GhsaVulnerability = NonNullable<GhsaApiAdvisory["vulnerabilities"]>[number];

function patchedVersions(v: GhsaVulnerability): string | null | undefined {
  if (typeof v.patched_versions === "string" && v.patched_versions.trim()) return v.patched_versions;
  return v.first_patched_version;
}

function severityScore(advisory: GhsaApiAdvisory): string {
  const raw = advisory.cvss_severities?.cvss_v3?.score;
  if (typeof raw === "number" && Number.isFinite(raw)) return String(raw);
  return GHSA_SEVERITY_SCORE[String(advisory.severity || "").toLowerCase()] ?? "3.0";
}

/** Build one OSV affected entry from a GitHub vulnerability record (null when unusable). */
function buildAffectedEntry(v: GhsaVulnerability, ecosystems: Set<string>) {
  const pkg = v.package || {};
  if (!pkg.name || !pkg.ecosystem) return null;
  const eco = String(pkg.ecosystem).toLowerCase();
  const osvEco = eco === "maven" ? "Maven" : pkg.ecosystem;
  ecosystems.add(osvEco);

  const entry = { package: { name: pkg.name, ecosystem: osvEco }, versions: [] as string[], ranges: [] as Array<Record<string, unknown>> };
  const r = parseGhsaRange(v.vulnerable_version_range);
  if (r?.exact !== undefined) {
    entry.versions.push(r.exact);
  } else if (r) {
    const introduced = r.gte ?? r.gt ?? "0";
    const events: Array<Record<string, string | boolean>> = [
      r.gt !== undefined && r.gte === undefined
        ? { introduced, introduced_exclusive: true }
        : { introduced },
    ];
    if (r.lte !== undefined) events.push({ last_affected: r.lte });
    if (r.lt !== undefined) events.push({ fixed: r.lt });
    const fixed = r.lt === undefined
      ? firstPatchedVersion(patchedVersions(v), eco === "maven" ? r.lte : undefined)
      : null;
    if (fixed) events.push({ fixed });
    entry.ranges.push({ type: "ECOSYSTEM", events });
  }
  return entry;
}

/** Build the links list for a GitHub advisory. */
function buildGhsaLinks(advisory: GhsaApiAdvisory): Array<{ url: string }> {
  const links: Array<{ url: string }> = [];
  if (advisory.html_url) {
    links.push({ url: advisory.html_url });
  } else if (advisory.ghsa_id) {
    links.push({ url: `https://github.com/github/advisories/database/${advisory.ghsa_id}` });
  }
  if (advisory.cve_id) links.push({ url: `https://nvd.nist.gov/vuln/detail/${advisory.cve_id}` });
  return links;
}

/** Convert one GitHub advisory into an OSV-shaped record (null if no usable packages). */
export function ghsaToOsv(advisory: GhsaApiAdvisory): AdvisoryEntry | null {
  if (advisory.withdrawn_at) return null;
  const vulns = Array.isArray(advisory?.vulnerabilities) ? advisory.vulnerabilities : [];
  const affected: AdvisoryEntry["affected"] = [];
  const ecosystems = new Set<string>();

  for (const v of vulns) {
    const entry = buildAffectedEntry(v, ecosystems);
    if (!entry) continue;
    affected.push(entry);
  }

  if (affected.length === 0) return null;

  return {
    id: advisory.ghsa_id,
    aliases: [advisory.cve_id].filter((x): x is string => Boolean(x)),
    ecosystems: [...ecosystems],
    summary: advisory.summary || `${advisory.ghsa_id} affects ${affected.map(a => a.package?.name).join(", ")}`,
    severity: [{ type: "CVSS_V3_1", score: severityScore(advisory) }],
    affected,
    links: buildGhsaLinks(advisory),
  };
}

export function extractNextLink(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  let from = 0;
  for (;;) {
    const start = linkHeader.indexOf("<", from);
    if (start === -1) return null;
    const end = linkHeader.indexOf(">", start + 1);
    if (end === -1 || end <= start + 1) {
      from = end === -1 ? linkHeader.length : end + 1;
      continue;
    }
    if (!/^;\s*rel="next"/.test(linkHeader.slice(end + 1))) {
      from = end + 1;
      continue;
    }
    try {
      const url = new URL(linkHeader.slice(start + 1, end));
      if (url.protocol !== "https:" || url.hostname !== "api.github.com") return null;
      return url.toString();
    } catch {
      return null;
    }
  }
}

export interface RepoAdvisoriesOptions {
  /** Bypass TTL and re-fetch */
  forceRefresh?: boolean;
  /** Spinner text updater */
  setText?: (msg: string) => void;
  /** Read the local cache only. Does not call the GitHub API. */
  offline?: boolean;
  /** Non-fatal notes (stale cache, missing offline cache). */
  onWarning?: (msg: string) => void;
  /** Called when cache/source coverage is incomplete. */
  onIncomplete?: () => void;
}

function githubHeaders(withAuth: boolean = true): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": "auto-bumper",
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": GHSA_API_VERSION,
  };
  if (withAuth) {
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

interface GhsaPage {
  records: AdvisoryEntry[];
  withdrawnIds: string[];
}

/** Shared per-run auth state: once a token is rejected, later pages go anonymous. */
interface GhsaAuthState { disabled: boolean; tokenRejected?: boolean }

/** Actionable error for GitHub API failures (rate-limit 403s say what to do). */
function ghsaHttpError(status: number, resp: Response, tokenRejected?: boolean): Error {
  const remaining = resp.headers.get("x-ratelimit-remaining");
  const reset = resp.headers.get("x-ratelimit-reset");
  if (status === 403 && (remaining === "0" || reset)) {
    const when = reset ? `${new Date(Number(reset) * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC` : "soon";
    if (tokenRejected) {
      return new Error(`GitHub API: GITHUB_TOKEN was rejected by GitHub and anonymous access is rate-limited (resets ${when}); refresh the token and re-run`);
    }
    return new Error(`GitHub API rate limit exceeded (resets ${when}); set GITHUB_TOKEN to raise the limit and re-run`);
  }
  if (status === 401 || status === 403) {
    return new Error(`GitHub API HTTP ${status} for Maven advisories — check GITHUB_TOKEN`);
  }
  return new Error(`GitHub API HTTP ${status} for Maven advisories`);
}

/** Follow Link rel=next. Stops when GitHub sends no further api.github.com page. */
async function fetchGhsaPages(
  startUrl: string,
  setText?: (msg: string) => void,
  auth: GhsaAuthState = { disabled: false },
  onPage?: (records: AdvisoryEntry[], withdrawnIds: string[]) => void,
): Promise<GhsaPage> {
  const records: AdvisoryEntry[] = [];
  const withdrawnIds: string[] = [];
  let url: string | null = startUrl;
  let page = 0;
  while (url) {
    page += 1;
    setText?.(`GitHub Maven advisories: page ${page}`);
    let resp = await fetchWithRetry(
      url,
      { headers: githubHeaders(!auth.disabled) },
      { label: "GitHub Maven advisories", retries: 3 },
    );
    if ((resp.status === 401 || resp.status === 403) && !auth.disabled) {
      // A stale or invalid token must not break the run: the endpoint is public, so retry once anonymously.
      auth.disabled = true;
      auth.tokenRejected = Boolean(process.env.GITHUB_TOKEN || process.env.GH_TOKEN);
      const anon = await fetchWithRetry(
        url,
        { headers: githubHeaders(false) },
        { label: "GitHub Maven advisories", retries: 3 },
      );
      if (anon.ok) resp = anon;
      else throw ghsaHttpError(anon.status, anon, auth.tokenRejected);
    }
    if (!resp.ok) throw ghsaHttpError(resp.status, resp);
    const items = (await resp.json()) as GhsaApiAdvisory[];
    if (!Array.isArray(items)) throw new Error("GitHub Maven advisories response was not a list");
    for (const item of items) {
      if (!item?.ghsa_id) continue;
      if (item.withdrawn_at) {
        withdrawnIds.push(item.ghsa_id);
        continue;
      }
      const rec = ghsaToOsv(item);
      if (rec) records.push(rec);
    }
    onPage?.(records, withdrawnIds);
    url = extractNextLink(resp.headers.get("link"));
  }
  return { records, withdrawnIds };
}

/**
 * Load reviewed GitHub Maven advisories.
 * A missing sync cursor downloads the full list and replaces the cache.
 * Later refreshes send `updated=>=` plus a withdrawn pass, then merge by id.
 * The cursor advances only after every page succeeds; while it is absent the
 * cache counts as incomplete and is re-synced even inside the TTL window.
 * A bootstrap that fails mid-way keeps the pages already fetched so the next
 * run completes the sync instead of starting over.
 */
export async function loadRepoAdvisories(opts: RepoAdvisoriesOptions = {}): Promise<AdvisoryEntry[]> {
  const { forceRefresh = false, setText, offline = false, onWarning, onIncomplete } = opts;
  const cached = readCacheFile(GHSA_REPO_CACHE);
  if (offline) {
    if (cached === null) {
      onWarning?.("GitHub Maven advisories cache missing; reviewed GHSAs were not matched. Run a scan online once.");
      onIncomplete?.();
      return [];
    }
    if (readGhsaSince() === null) onIncomplete?.();
    return cached;
  }
  if (!forceRefresh) {
    const age = getCacheAgeMs(GHSA_REPO_CACHE);
    // No sync cursor means the last sync did not finish: re-sync regardless of TTL.
    if (cached !== null && readGhsaSince() !== null && age !== null && age < CACHE_TTL_MS) return cached;
  }

  const since = cached !== null ? readGhsaSince() : null;
  const startedAt = formatGhsaSince(new Date());
  const auth: GhsaAuthState = { disabled: false };
  let partial: AdvisoryEntry[] = [];
  try {
    const active = await fetchGhsaPages(globalMavenAdvisoriesUrl(since, false), setText, auth, records => {
      partial = records;
    });
    let withdrawnIds = active.withdrawnIds;
    if (since) {
      const withdrawn = await fetchGhsaPages(globalMavenAdvisoriesUrl(since, true), setText, auth);
      withdrawnIds = [
        ...withdrawnIds,
        ...withdrawn.withdrawnIds,
        ...withdrawn.records.map(record => record.id),
      ];
    }

    if (!since && active.records.length === 0) {
      if (cached !== null && cached.length > 0) {
        onWarning?.("GitHub Maven advisories returned an empty list; using cached copy");
        if (readGhsaSince() === null) onIncomplete?.();
        return cached;
      }
      onWarning?.("GitHub Maven advisories returned an empty list");
      return [];
    }

    const records = since
      ? mergeGhsaAdvisories(cached ?? [], active.records, new Set(withdrawnIds))
      : active.records;
    writeCacheFile(GHSA_REPO_CACHE, records);
    writeGhsaSince(startedAt);
    return records;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (cached === null && partial.length > 0) {
      // Keep the pages that arrived; no cursor is written, so the next run re-syncs from scratch.
      writeCacheFile(GHSA_REPO_CACHE, partial);
      onWarning?.(`GitHub Maven advisories sync failed after ${partial.length} entries (${msg}); kept a partial cache — re-run to complete the sync`);
      onIncomplete?.();
      return partial;
    }
    if (cached !== null) {
      onWarning?.(`GitHub Maven advisories unavailable (${msg}); using cached copy`);
      if (readGhsaSince() === null) onIncomplete?.();
      return cached;
    }
    throw new Error(`GitHub Maven advisories unavailable (${msg}) and no cache exists`);
  }
}
