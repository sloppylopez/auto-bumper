import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it, mock } from "bun:test";
// Type-only: erased at compile time, so this does not trigger scan.ts evaluation early.
import type { ScanResult } from "../src/scan.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-ghsa-"));
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;
const dbDir = path.join(tmpRoot, "db", "osv");

// Mock the OSV bulk dump (returns nothing: the advisory under test is absent from OSV).
const actualOsvExport = await import("../src/lib/osv-export.ts");
const dumpMock = mock(async (_name: string): Promise<{ entries: unknown[]; etag: string | null }> => ({ entries: [], etag: null }));
mock.module("../src/lib/osv-export.ts", () => ({ ...actualOsvExport, downloadOsvEcosystemDump: dumpMock }));

// Dynamic imports (not static): scan.ts and github-repo-advisories.ts freeze paths derived from
// AUTO_BUMPER_CACHE_DIR at module evaluation, so the env var above must be set first.
const {
  loadRepoAdvisories,
  ghsaToOsv,
  parseGhsaRange,
  globalMavenAdvisoriesUrl,
  mergeGhsaAdvisories,
  readGhsaSince,
  getGhsaSincePath,
} = await import("../src/lib/github-repo-advisories.ts");
const { matchVulnerabilities } = await import("../src/lib/matcher.ts");
const { DB_DIR, runAutoBumperScan } = await import("../src/scan.ts");

const scanDbDir = DB_DIR;
const sinceFile = getGhsaSincePath();

function clearGhsaCache(): void {
  fs.rmSync(path.join(dbDir, "repo-advisories.json.gz"), { force: true });
  fs.rmSync(path.join(dbDir, "repo-advisories.json"), { force: true });
  fs.rmSync(sinceFile, { force: true });
}

const nettyAdvisory = {
  ghsa_id: "GHSA-q9pg-8h3j-8hvm",
  cve_id: null,
  severity: "medium",
  summary: "[codec-http3] Lack of Host header deduplication in HTTP/3 request handling leads to request routing bypass",
  html_url: "https://github.com/netty/netty/security/advisories/GHSA-q9pg-8h3j-8hvm",
  vulnerabilities: [
    {
      package: { ecosystem: "Maven", name: "io.netty:netty-codec-http3" },
      vulnerable_version_range: ">= 4.2.0.Final, <= 4.2.17.Final",
      patched_versions: "4.2.18.Final",
    },
  ],
};

const originalFetch = globalThis.fetch;

afterAll(() => {
  globalThis.fetch = originalFetch;
  delete process.env.AUTO_BUMPER_CACHE_DIR;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
  // If another test file evaluated scan.ts first, fixtures live under that file's tmp root.
  const frozenRoot = path.resolve(DB_DIR, "..", "..");
  if (frozenRoot !== tmpRoot && frozenRoot.startsWith(os.tmpdir())) {
    fs.rmSync(frozenRoot, { recursive: true, force: true });
  }
});

describe("parseGhsaRange", () => {
  it("parses exact ranges", () => {
    expect(parseGhsaRange("= 1.2.3")).toEqual({ exact: "1.2.3" });
  });

  it("parses gte/lte ranges", () => {
    expect(parseGhsaRange(">= 4.2.0.Final, <= 4.2.17.Final")).toEqual({ gte: "4.2.0.Final", lte: "4.2.17.Final" });
  });

  it("parses open-ended ranges", () => {
    expect(parseGhsaRange(">= 1.0")).toEqual({ gte: "1.0" });
    expect(parseGhsaRange("<= 2.0")).toEqual({ lte: "2.0" });
  });

  it("returns null for empty input", () => {
    expect(parseGhsaRange(null)).toBeNull();
    expect(parseGhsaRange("")).toBeNull();
  });
});

describe("ghsaToOsv", () => {
  it("converts a maven range advisory with inclusive upper bound and patched version", () => {
    const rec = ghsaToOsv(nettyAdvisory);
    expect(rec?.id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(rec?.affected[0].ranges).toEqual([
      {
        type: "ECOSYSTEM",
        events: [
          { introduced: "4.2.0.Final" },
          { last_affected: "4.2.17.Final" },
          { fixed: "4.2.18.Final" },
        ],
      },
    ]);
    expect(rec?.links.some(l => l.url.startsWith("https://github.com/netty/"))).toBe(true);
  });

  it("converts exact ranges into versions", () => {
    const rec = ghsaToOsv({
      ...nettyAdvisory,
      vulnerabilities: [{ package: nettyAdvisory.vulnerabilities![0].package, vulnerable_version_range: "= 1.2.3" }],
    });
    expect(rec?.affected[0].versions).toEqual(["1.2.3"]);
    expect(rec?.affected[0].ranges).toEqual([]);
  });

  it("skips maven patched versions at or below the inclusive upper bound", () => {
    const rec = ghsaToOsv({
      ...nettyAdvisory,
      vulnerabilities: [
        {
          package: nettyAdvisory.vulnerabilities![0].package,
          vulnerable_version_range: ">= 2.0, <= 2.5",
          patched_versions: "2.4, 2.6",
        },
      ],
    });
    expect(rec?.affected[0].ranges).toEqual([
      {
        type: "ECOSYSTEM",
        events: [
          { introduced: "2.0" },
          { last_affected: "2.5" },
          { fixed: "2.6" },
        ],
      },
    ]);
  });

  it("maps CVE id to aliases and an NVD link", () => {
    const rec = ghsaToOsv({ ...nettyAdvisory, cve_id: "CVE-2026-100661" });
    expect(rec?.aliases).toEqual(["CVE-2026-100661"]);
    expect(rec?.links.some(l => l.url === "https://nvd.nist.gov/vuln/detail/CVE-2026-100661")).toBe(true);
  });

  it("uses the global API first_patched_version and the numeric CVSS score", () => {
    const rec = ghsaToOsv({
      ghsa_id: "GHSA-cvss-1111-2222",
      severity: "high",
      cvss_severities: { cvss_v3: { score: 9.8 } },
      vulnerabilities: [
        {
          package: { ecosystem: "maven", name: "com.google.guava:guava" },
          vulnerable_version_range: ">= 30.0, <= 33.6.0-jre",
          first_patched_version: "33.7.2-jre",
        },
      ],
    });
    expect(rec?.severity).toEqual([{ type: "CVSS_V3_1", score: "9.8" }]);
    expect(rec?.affected[0].ranges).toEqual([
      {
        type: "ECOSYSTEM",
        events: [
          { introduced: "30.0" },
          { last_affected: "33.6.0-jre" },
          { fixed: "33.7.2-jre" },
        ],
      },
    ]);
  });

  it("returns null for a withdrawn advisory and for no usable packages", () => {
    expect(ghsaToOsv({ ...nettyAdvisory, withdrawn_at: "2026-10-01T00:00:00Z" })).toBeNull();
    expect(ghsaToOsv({ ghsa_id: "GHSA-empty" })).toBeNull();
    expect(ghsaToOsv({ ghsa_id: "GHSA-nopkg", vulnerabilities: [{ package: {} }] })).toBeNull();
  });
});

describe("global Maven advisory query", () => {
  it("asks GitHub for reviewed Maven rows and never sends a package list", () => {
    const url = new URL(globalMavenAdvisoriesUrl(null, false));
    expect(url.origin + url.pathname).toBe("https://api.github.com/advisories");
    expect(url.searchParams.get("ecosystem")).toBe("maven");
    expect(url.searchParams.get("type")).toBe("reviewed");
    expect(url.searchParams.get("per_page")).toBe("100");
    expect(url.searchParams.get("sort")).toBe("updated");
    expect(url.searchParams.has("affects")).toBe(false);
    expect(url.searchParams.has("updated")).toBe(false);
    expect(url.toString()).not.toContain("io.netty");
  });

  it("limits a later pull to updates since the cursor, and can ask only for withdrawn rows", () => {
    const url = new URL(globalMavenAdvisoriesUrl("2026-10-16T10:00:00Z", true));
    expect(url.searchParams.get("updated")).toBe(">=2026-10-16T10:00:00Z");
    expect(url.searchParams.get("is_withdrawn")).toBe("true");
    expect(url.searchParams.has("affects")).toBe(false);
  });
});

describe("mergeGhsaAdvisories", () => {
  const entry = (id: string) => ({
    id,
    aliases: [] as string[],
    ecosystems: ["Maven"],
    summary: id,
    severity: [] as Array<{ type: string; score: string }>,
    affected: [] as Array<{ package?: { name?: string; ecosystem?: string }; versions?: string[]; ranges?: unknown[] }>,
    links: [] as Array<{ url: string }>,
  });

  it("replaces the same id and drops withdrawn ids", () => {
    const merged = mergeGhsaAdvisories(
      [entry("GHSA-old"), entry("GHSA-keep")],
      [entry("GHSA-new"), { ...entry("GHSA-keep"), summary: "fresh" }],
      new Set(["GHSA-old"]),
    );
    expect(merged.map(r => r.id).sort()).toEqual(["GHSA-keep", "GHSA-new"]);
    expect(merged.find(r => r.id === "GHSA-keep")?.summary).toBe("fresh");
  });
});

describe("loadRepoAdvisories", () => {
  const fetchMock = mock(async (url: string | URL): Promise<Response> => {
    const parsed = new URL(String(url));
    if (parsed.searchParams.get("is_withdrawn") === "true") {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    return new Response(JSON.stringify([nettyAdvisory]), { status: 200 });
  });
  globalThis.fetch = fetchMock;

  function calledUrls(): URL[] {
    return fetchMock.mock.calls.map(call => new URL(String(call[0])));
  }

  it("fetches the global Maven list, converts it, and stores the sync cursor", async () => {
    clearGhsaCache();
    fetchMock.mockClear();
    const recs = await loadRepoAdvisories();
    expect(recs).toHaveLength(1);
    expect(recs[0].id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(fs.existsSync(path.join(dbDir, "repo-advisories.json.gz"))).toBe(true);
    expect(readGhsaSince()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    const url = calledUrls()[0];
    expect(url?.pathname).toBe("/advisories");
    expect(url?.searchParams.get("ecosystem")).toBe("maven");
    expect(url?.searchParams.has("affects")).toBe(false);
    expect(url?.searchParams.has("updated")).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries anonymously when a stale token is rejected with 401", async () => {
    clearGhsaCache();
    fetchMock.mockClear();
    const oldToken = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = "ghp_stale-test-token";
    try {
      fetchMock.mockImplementation(async (url: string | URL, init?: RequestInit) => {
        const headers = (init?.headers ?? {}) as Record<string, string>;
        if (headers.Authorization) return new Response("Unauthorized", { status: 401 });
        return new Response(JSON.stringify([nettyAdvisory]), { status: 200 });
      });
      const recs = await loadRepoAdvisories();
      expect(recs).toHaveLength(1);
      expect(recs[0].id).toBe("GHSA-q9pg-8h3j-8hvm");
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const authed = fetchMock.mock.calls.some(call => {
        const headers = ((call[1] as RequestInit | undefined)?.headers ?? {}) as Record<string, string>;
        return Boolean(headers.Authorization);
      });
      expect(authed).toBe(true);
    } finally {
      if (oldToken === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = oldToken;
    }
  });

  it("serves from cache within TTL without re-fetching", async () => {
    fetchMock.mockClear();
    const recs = await loadRepoAdvisories();
    expect(recs).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("on a later refresh asks only for rows updated since the cursor", async () => {
    const cursor = readGhsaSince();
    fetchMock.mockClear();
    const fresh = {
      ...nettyAdvisory,
      ghsa_id: "GHSA-new1-aaaa-bbbb",
      summary: "later advisory",
    };
    fetchMock.mockImplementation(async (url: string | URL) => {
      const parsed = new URL(String(url));
      if (parsed.searchParams.get("is_withdrawn") === "true") {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      return new Response(JSON.stringify([fresh]), { status: 200 });
    });
    const recs = await loadRepoAdvisories({ forceRefresh: true });
    const urls = calledUrls();
    expect(urls).toHaveLength(2);
    expect(urls[0].searchParams.get("updated")).toBe(`>=${cursor}`);
    expect(urls[0].searchParams.has("affects")).toBe(false);
    expect(urls[1].searchParams.get("is_withdrawn")).toBe("true");
    expect(recs.map(r => r.id).sort()).toEqual(["GHSA-new1-aaaa-bbbb", "GHSA-q9pg-8h3j-8hvm"]);
  });

  it("drops an advisory that GitHub has withdrawn since the cursor", async () => {
    fetchMock.mockClear();
    fetchMock.mockImplementation(async (url: string | URL) => {
      const parsed = new URL(String(url));
      if (parsed.searchParams.get("is_withdrawn") === "true") {
        return new Response(JSON.stringify([{ ...nettyAdvisory, withdrawn_at: "2026-10-16T00:00:00Z" }]), { status: 200 });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    });
    const recs = await loadRepoAdvisories({ forceRefresh: true });
    expect(recs.map(r => r.id)).not.toContain("GHSA-q9pg-8h3j-8hvm");
    expect(recs.map(r => r.id)).toContain("GHSA-new1-aaaa-bbbb");
  });

  it("follows Link-header pagination on a full pull", async () => {
    clearGhsaCache();
    const base = globalMavenAdvisoriesUrl(null, false);
    fetchMock.mockClear();
    fetchMock.mockImplementation(async (url: string | URL) => {
      if (String(url).includes("cursor=2")) {
        return new Response(JSON.stringify([{ ...nettyAdvisory, ghsa_id: "GHSA-page2-aaaa-bbbb" }]), { status: 200 });
      }
      const link = `<${base}&cursor=2>; rel="next"`;
      return new Response(JSON.stringify([nettyAdvisory]), { status: 200, headers: { link } });
    });

    const recs = await loadRepoAdvisories({ forceRefresh: true });
    expect(recs.map(r => r.id)).toEqual(["GHSA-q9pg-8h3j-8hvm", "GHSA-page2-aaaa-bbbb"]);
    expect(calledUrls().every(url => url.searchParams.get("ecosystem") === "maven")).toBe(true);
  });

  it("reads the cache offline and does not call GitHub", async () => {
    fetchMock.mockClear();
    const recs = await loadRepoAdvisories({ offline: true });
    expect(recs[0]?.id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends GITHUB_TOKEN when set", async () => {
    clearGhsaCache();
    process.env.GITHUB_TOKEN = "test-token";
    let auth: string | null = null;
    fetchMock.mockImplementation(async (_url: string | URL, init?: RequestInit) => {
      auth = new Headers(init?.headers).get("authorization");
      return new Response(JSON.stringify([nettyAdvisory]), { status: 200 });
    });
    try {
      await loadRepoAdvisories({ forceRefresh: true });
    } finally {
      delete process.env.GITHUB_TOKEN;
    }
    expect(auth).toBe("Bearer test-token");
  });

  it("keeps the stale cache and does not move the cursor when GitHub fails", async () => {
    const cursor = readGhsaSince();
    const gz = path.join(dbDir, "repo-advisories.json.gz");
    const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    fs.utimesSync(gz, old, old);
    fetchMock.mockImplementation(async () => {
      throw new Error("rate limited");
    });
    const warnings: string[] = [];
    const recs = await loadRepoAdvisories({ onWarning: (msg) => warnings.push(msg) });
    expect(recs[0]?.id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(warnings[0]).toContain("using cached copy");
    expect(readGhsaSince()).toBe(cursor);
  });

  it("refuses to replace a cached list with an empty full pull", async () => {
    fs.rmSync(sinceFile, { force: true });
    const gz = path.join(dbDir, "repo-advisories.json.gz");
    const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    fs.utimesSync(gz, old, old);
    fetchMock.mockImplementation(async () => new Response(JSON.stringify([]), { status: 200 }));
    const warnings: string[] = [];
    const recs = await loadRepoAdvisories({ onWarning: (msg) => warnings.push(msg) });
    expect(recs[0]?.id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(warnings[0]).toContain("empty list");
    expect(readGhsaSince()).toBeNull();
  });

  it("throws when fetch fails and no cache exists", async () => {
    clearGhsaCache();
    fetchMock.mockImplementation(async () => new Response("no", { status: 403 }));
    await expect(loadRepoAdvisories({ forceRefresh: true })).rejects.toThrow(/no cache exists/);
  });

  it("keeps a partial cache when bootstrap fails mid-pagination, then completes it", async () => {
    clearGhsaCache();
    const base = globalMavenAdvisoriesUrl(null, false);
    fetchMock.mockClear();
    // Run 1: page 2 fails. The first page must survive as a partial cache.
    fetchMock.mockImplementation(async (url: string | URL) => {
      if (String(url).includes("cursor=2")) return new Response("boom", { status: 500 });
      const link = `<${base}&cursor=2>; rel="next"`;
      return new Response(JSON.stringify([nettyAdvisory]), { status: 200, headers: { link } });
    });
    const warnings: string[] = [];
    const partialRecs = await loadRepoAdvisories({ onWarning: (msg) => warnings.push(msg) });
    expect(partialRecs.map(r => r.id)).toEqual(["GHSA-q9pg-8h3j-8hvm"]);
    expect(warnings[0]).toContain("partial cache");
    expect(fs.existsSync(path.join(dbDir, "repo-advisories.json.gz"))).toBe(true);
    expect(readGhsaSince()).toBeNull();

    // Run 2: everything succeeds. The missing sync cursor must bypass the TTL gate.
    fetchMock.mockClear();
    fetchMock.mockImplementation(async (url: string | URL) => {
      if (String(url).includes("cursor=2")) {
        return new Response(JSON.stringify([{ ...nettyAdvisory, ghsa_id: "GHSA-page2-aaaa-bbbb" }]), { status: 200 });
      }
      const link = `<${base}&cursor=2>; rel="next"`;
      return new Response(JSON.stringify([nettyAdvisory]), { status: 200, headers: { link } });
    });
    const fullRecs = await loadRepoAdvisories();
    expect(fullRecs.map(r => r.id)).toEqual(["GHSA-q9pg-8h3j-8hvm", "GHSA-page2-aaaa-bbbb"]);
    expect(readGhsaSince()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it("stops using a rejected token for later pages", async () => {
    clearGhsaCache();
    const base = globalMavenAdvisoriesUrl(null, false);
    fetchMock.mockClear();
    process.env.GITHUB_TOKEN = "ghp_stale-test-token";
    const page2Headers: Array<Record<string, string>> = [];
    try {
      fetchMock.mockImplementation(async (url: string | URL, init?: RequestInit) => {
        const headers = (init?.headers ?? {}) as Record<string, string>;
        if (String(url).includes("cursor=2")) {
          page2Headers.push(headers);
          return new Response(JSON.stringify([{ ...nettyAdvisory, ghsa_id: "GHSA-page2-aaaa-bbbb" }]), { status: 200 });
        }
        if (headers.Authorization) return new Response("Unauthorized", { status: 401 });
        const link = `<${base}&cursor=2>; rel="next"`;
        return new Response(JSON.stringify([nettyAdvisory]), { status: 200, headers: { link } });
      });
      const recs = await loadRepoAdvisories();
      expect(recs.map(r => r.id)).toEqual(["GHSA-q9pg-8h3j-8hvm", "GHSA-page2-aaaa-bbbb"]);
      expect(page2Headers.length).toBeGreaterThan(0);
      expect(page2Headers.every(h => h.Authorization === undefined)).toBe(true);
    } finally {
      delete process.env.GITHUB_TOKEN;
    }
  });

  it("turns an anonymous rate-limit 403 into an actionable error", async () => {
    clearGhsaCache();
    fetchMock.mockClear();
    const oldToken = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    try {
      const reset = String(Math.floor(Date.now() / 1000) + 900);
      fetchMock.mockImplementation(async () => new Response("rate limited", {
        status: 403,
        headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": reset },
      }));
      await expect(loadRepoAdvisories()).rejects.toThrow(/rate limit exceeded.*set GITHUB_TOKEN/s);
      expect(fs.existsSync(path.join(dbDir, "repo-advisories.json.gz"))).toBe(false);
    } finally {
      if (oldToken !== undefined) process.env.GITHUB_TOKEN = oldToken;
    }
  });

  it("names a rejected token when anonymous access is also rate-limited", async () => {
    clearGhsaCache();
    fetchMock.mockClear();
    const oldToken = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = "ghp_stale-test-token";
    try {
      const reset = String(Math.floor(Date.now() / 1000) + 900);
      fetchMock.mockImplementation(async () => new Response("rate limited", {
        status: 403,
        headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": reset },
      }));
      await expect(loadRepoAdvisories()).rejects.toThrow(/GITHUB_TOKEN was rejected.*refresh the token/s);
    } finally {
      if (oldToken === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = oldToken;
    }
  });
});

describe("OSV bulk + repo advisories dedup", () => {
  it("merges a CVE-id bulk record with an alias-matching GHSA repo record into one finding", () => {
    const pkg = { ecosystem: "maven", name: "io.netty:netty-codec-http3", version: "4.2.17.Final", manifestPath: "pom.xml" };
    const range = (events: unknown[]) => [
      { package: { name: pkg.name, ecosystem: "Maven" }, versions: [], ranges: [{ type: "ECOSYSTEM", events }] },
    ];
    const bulk = {
      id: "CVE-2026-100661",
      aliases: [],
      ecosystems: ["Maven"],
      summary: "bulk record",
      severity: [{ type: "CVSS_V3_1", score: "7.5" }],
      affected: range([{ introduced: "4.2.0.Final" }, { fixed: "4.2.18.Final" }]),
      links: [],
    };
    const repo = {
      id: "GHSA-aaaa-bbbb-cccc",
      aliases: ["CVE-2026-100661"],
      ecosystems: ["Maven"],
      summary: "repo record",
      severity: [{ type: "CVSS_V3_1", score: "9.8" }],
      affected: range([{ introduced: "4.2.0.Final" }, { last_affected: "4.2.17.Final" }, { fixed: "4.2.18.Final" }]),
      links: [],
    };

    const findings = matchVulnerabilities([pkg], [bulk, repo]);

    expect(findings).toHaveLength(1);
    // mergeFinding keeps the first record's id (the bulk CVE) and unions aliases; the GHSA
    // primary id is not promoted — shared matcher semantics, parity with the extension.
    expect(findings[0].id).toBe("CVE-2026-100661");
    expect(findings[0].severity).toBe("CRITICAL"); // 9.8 from the repo record wins over 7.5
  });
});

describe("scan integration: repo advisories find what OSV bulk misses", () => {
  it("flags netty-codec-http3 4.2.17.Final via a GHSA-only advisory", async () => {
    const proj = path.join(tmpRoot, "proj");
    fs.mkdirSync(proj, { recursive: true });
    fs.writeFileSync(
      path.join(proj, "pom.xml"),
      `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>fixture</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-codec-http3</artifactId>
      <version>4.2.17.Final</version>
    </dependency>
  </dependencies>
</project>
`,
    );

    // No OSV bulk cache and an empty dump: the advisory is absent from OSV.
    fs.rmSync(path.join(scanDbDir, "Maven.json.gz"), { force: true });
    clearGhsaCache();
    dumpMock.mockClear();
    dumpMock.mockResolvedValue({ entries: [], etag: null });

    const scanFetch = mock(async (url: string | URL) => {
      if (String(url).includes("api.github.com")) {
        return new Response(JSON.stringify([nettyAdvisory]), { status: 200 });
      }
      return new Response(null, { status: 404 }); // OSV API → nothing
    });
    globalThis.fetch = scanFetch;

    const savedPath = process.env.PATH;
    process.env.PATH = process.platform === "win32" ? "C:\\Windows" : "/nonexistent"; // hide mvn → direct pom parse
    let result: ScanResult;
    try {
      result = await runAutoBumperScan(proj, { quiet: true });
    } finally {
      process.env.PATH = savedPath;
    }

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(result.findings[0].packageName).toBe("io.netty:netty-codec-http3");
  });
});
