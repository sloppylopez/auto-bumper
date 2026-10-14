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
const { loadRepoAdvisories, getWatchedRepos, ghsaToOsv, parseGhsaRange, DEFAULT_WATCHED_REPOS } = await import(
  "../src/lib/github-repo-advisories.ts"
);
const { matchVulnerabilities } = await import("../src/lib/matcher.ts");
const { DB_DIR, runAutoBumperScan } = await import("../src/scan.ts");

// scan.ts freezes its cache dir at first evaluation (bun test shares one module registry across
// files), so the Maven bulk cache and the watchlist file live under that frozen dir. The
// repo-advisories cache is resolved from env at call time, so it stays in tmpRoot/db/osv.
const scanDbDir = DB_DIR;
const watchlistFile = path.resolve(DB_DIR, "..", "..", "ghsa-repos.json");

// Limit the watchlist to one repo so every test hits a single API endpoint.
fs.mkdirSync(path.dirname(watchlistFile), { recursive: true });
fs.writeFileSync(watchlistFile, JSON.stringify(["netty/netty"]));

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

  it("returns null when no usable packages", () => {
    expect(ghsaToOsv({ ghsa_id: "GHSA-empty" })).toBeNull();
    expect(ghsaToOsv({ ghsa_id: "GHSA-nopkg", vulnerabilities: [{ package: {} }] })).toBeNull();
  });
});

describe("getWatchedRepos", () => {
  it("uses the override watchlist file", () => {
    expect(getWatchedRepos()).toEqual(["netty/netty"]);
  });

  it("falls back to defaults on a malformed override", () => {
    fs.writeFileSync(watchlistFile, JSON.stringify(["no-slash-here"]));
    expect(getWatchedRepos()).toEqual(DEFAULT_WATCHED_REPOS);
    fs.writeFileSync(watchlistFile, JSON.stringify(["netty/netty"])); // restore
  });
});

describe("loadRepoAdvisories", () => {
  const fetchMock = mock(async (_url: string | URL): Promise<Response> => new Response(JSON.stringify([nettyAdvisory]), { status: 200 }));
  globalThis.fetch = fetchMock;

  it("fetches, converts and caches records", async () => {
    const recs = await loadRepoAdvisories();
    expect(recs).toHaveLength(1);
    expect(recs[0].id).toBe("GHSA-q9pg-8h3j-8hvm");
    expect(fs.existsSync(path.join(dbDir, "repo-advisories.json.gz"))).toBe(true);
  });

  it("serves from cache within TTL without re-fetching", async () => {
    fetchMock.mockClear();
    const recs = await loadRepoAdvisories();
    expect(recs).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("re-fetches on forceRefresh", async () => {
    fetchMock.mockClear();
    await loadRepoAdvisories({ forceRefresh: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("follows Link-header pagination cursors", async () => {
    const base = "https://api.github.com/repos/netty/netty/security-advisories?per_page=100";
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
    fs.rmSync(path.join(dbDir, "repo-advisories.json.gz"), { force: true });
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
