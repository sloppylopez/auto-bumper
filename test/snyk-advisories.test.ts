import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "snyk-advisories-test-"));
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;

// getOsvDbDir reads AUTO_BUMPER_CACHE_DIR per call, so a static import is safe; the env
// override above still keeps every cache write inside tmpRoot.
import {
  snykPackageUrl,
  parseSnykPackagePage,
  snykVulnToOsv,
  loadSnykAdvisories,
  getSnykCacheDir,
} from "../src/lib/snyk-advisories.ts";

// scan-cache-freshness.test.ts installs a process-wide mock.module for fetch-retry (a 404 stub);
// bun's mock.module persists across test files, so in a full-suite run loadSnykAdvisories'
// fetchWithRetry may be that stub by the time this file executes. Reinstall a passthrough to
// globalThis.fetch so the per-test wrapper below is what actually runs (same pattern as
// scan-cache-freshness itself). Files running after this one either stub globalThis.fetch per
// test or never touch fetch, so the passthrough is safe for them.
const actualFetchRetry = await import("../src/lib/fetch-retry.ts");
mock.module("../src/lib/fetch-retry.ts", () => ({
  ...actualFetchRetry,
  fetchWithRetry: mock(async (input: string | URL, init?: RequestInit): Promise<Response> => globalThis.fetch(input, init)),
}));

const FIXTURE = fs.readFileSync(path.join(import.meta.dir, "fixtures", "snyk-package-netty.html"), "utf8");

// ─── fetch mock ─────────────────────────────────────
const realFetch = globalThis.fetch;
let fetchCalls: string[] = [];
let fetchImpl: (url: string) => Promise<Response>;

beforeEach(() => {
  fetchCalls = [];
  fetchImpl = async () => new Response("", { status: 200 });
});
const snykFetchWrapper = (async (url: RequestInfo | URL) => {
  const u = String(url);
  fetchCalls.push(u);
  return fetchImpl(u);
}) as typeof fetch;
globalThis.fetch = snykFetchWrapper;

afterAll(() => {
  globalThis.fetch = realFetch;
  delete process.env.AUTO_BUMPER_CACHE_DIR;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function mavenPkg(name: string, version = "1.0.0") {
  return { name, version, ecosystem: "Maven" as const };
}
function npmPkg(name: string, version = "1.0.0") {
  return { name, version, ecosystem: "npm" as const };
}

describe("snykPackageUrl", () => {
  test("encodes the maven colon", () => {
    expect(snykPackageUrl("Maven", "io.netty:netty-codec-socks")).toBe(
      "https://security.snyk.io/package/maven/io.netty%3Anetty-codec-socks",
    );
  });

  test("plain and scoped npm names", () => {
    expect(snykPackageUrl("npm", "lodash")).toBe("https://security.snyk.io/package/npm/lodash");
    expect(snykPackageUrl("npm", "@scope/pkg")).toBe("https://security.snyk.io/package/npm/%40scope%2Fpkg");
  });
});

describe("parseSnykPackagePage", () => {
  test("extracts the vulnerability list from a real Nuxt payload", () => {
    const vulns = parseSnykPackagePage(FIXTURE);
    expect(vulns.length).toBe(1);
    const v = vulns[0];
    expect(v.id).toBe("SNYK-JAVA-IONETTY-19233598");
    expect(v.severity).toBe("medium");
    expect(v.identifiers?.CVE).toEqual(["CVE-2026-62380"]);
    expect(v.identifiers?.GHSA).toEqual(["GHSA-cc6x-ffm5-83wf"]);
    expect(v.affectedVersions).toEqual([
      { min: null, max: { version: "4.1.137.Final", inclusive: false } },
      { min: { version: "4.2.0.Final", inclusive: true }, max: { version: "4.2.17.Final", inclusive: false } },
    ]);
  });

  test("throws on a page without the payload", () => {
    expect(() => parseSnykPackagePage("<html>not a snyk page</html>").length).toThrow();
  });

  test("throws when the payload has no vulnerabilities array", () => {
    const html = `<script id="__NUXT_DATA__">${JSON.stringify([{ description: "x" }])}</script>`;
    expect(() => parseSnykPackagePage(html)).toThrow(/vulnerabilities/);
  });

  test("an empty vulnerabilities array is a real empty result", () => {
    const html = `<script id="__NUXT_DATA__">${JSON.stringify([{ vulnerabilities: [] }])}</script>`;
    expect(parseSnykPackagePage(html)).toEqual([]);
  });

  test("does not pollute Object.prototype from payload keys", () => {
    const html = `<script id="__NUXT_DATA__">${JSON.stringify([
      ["Object", 1, 2, 3, 4],
      "vulnerabilities",
      ["Array", 5],
      "__proto__",
      { polluted: true },
      ["Object", 6, 7],
      "id",
      "SNYK-OBJ",
    ])}</script>`;
    try {
      const vulns = parseSnykPackagePage(html);
      expect(vulns.map((v) => v.id)).toEqual(["SNYK-OBJ"]);
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    } finally {
      delete (Object.prototype as { polluted?: boolean }).polluted;
    }
  });
});

describe("snykVulnToOsv", () => {
  const withCve = {
    id: "SNYK-JAVA-FOO-1",
    title: "Foo is vulnerable",
    severity: "high",
    affectedVersions: [
      { min: null, max: { version: "2.0.0", inclusive: false } },
      { min: { version: "3.0.0", inclusive: true }, max: null },
    ],
    identifiers: { CVE: ["CVE-2026-1111"], GHSA: ["GHSA-abcd-efgh-ijkl"] },
  };

  test("uses the primary CVE as id and carries all aliases", () => {
    const e = snykVulnToOsv(withCve, "com.foo:bar", "Maven")!;
    expect(e.id).toBe("CVE-2026-1111");
    expect(e.aliases).toEqual(["SNYK-JAVA-FOO-1", "CVE-2026-1111", "GHSA-abcd-efgh-ijkl"]);
    expect(e.ecosystems).toEqual(["Maven"]);
    expect(e.affected[0].package.name).toBe("com.foo:bar");
    expect(e.severity).toEqual([{ type: "CVSS_V3_1", score: "7.5" }]);
    // exclusive upper bound → fixed event; open window → introduced only
    expect(e.affected[0].ranges).toEqual([
      { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0.0" }] },
      { type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }] },
    ]);
    expect(e.links[0].url).toBe("https://security.snyk.io/vuln/SNYK-JAVA-FOO-1");
    expect(e.links[1].url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2026-1111");
  });

  test("inclusive upper bound becomes last_affected", () => {
    const e = snykVulnToOsv(
      { id: "SNYK-X", affectedVersions: [{ min: { version: "1.0.0", inclusive: true }, max: { version: "1.5.0", inclusive: true } }] },
      "lodash",
      "npm",
    )!;
    expect(e.affected[0].ranges).toEqual([
      { type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { last_affected: "1.5.0" }] },
    ]);
  });

  test("no CVE keeps the SNYK id", () => {
    const e = snykVulnToOsv({ id: "SNYK-JAVA-ORGECLIPSEPARSSON-17817925", severity: "high", affectedVersions: [] }, "org.glassfish:parsson", "Maven")!;
    expect(e.id).toBe("SNYK-JAVA-ORGECLIPSEPARSSON-17817925");
    expect(e.aliases).toEqual(["SNYK-JAVA-ORGECLIPSEPARSSON-17817925"]);
    expect(e.severity).toEqual([{ type: "CVSS_V3_1", score: "7.5" }]);
  });

  test("numeric cvssScore wins over the label; a missing label falls back to 3.0", () => {
    const unknown = snykVulnToOsv({ id: "SNYK-X", affectedVersions: [] }, "lodash", "npm")!;
    expect(unknown.severity).toEqual([{ type: "CVSS_V3_1", score: "3.0" }]);
    const scored = snykVulnToOsv({ id: "SNYK-Y", severity: "low", cvssScore: 9.8, affectedVersions: [] }, "lodash", "npm")!;
    expect(scored.severity).toEqual([{ type: "CVSS_V3_1", score: "9.8" }]);
  });

  test("exclusive lower bound stays an inclusive introduced event", () => {
    // OSV `introduced` is inclusive. An exclusive Snyk min still includes that version.
    const e = snykVulnToOsv(
      { id: "SNYK-X", affectedVersions: [{ min: { version: "1.0.0", inclusive: false }, max: { version: "2.0.0", inclusive: false } }] },
      "lodash",
      "npm",
    )!;
    expect(e.affected[0].ranges).toEqual([
      { type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] },
    ]);
  });

  test("returns null for an entry without id", () => {
    expect(snykVulnToOsv({ id: "" }, "lodash", "npm")).toBeNull();
  });
});

describe("loadSnykAdvisories", () => {
  const netty = mavenPkg("io.netty:netty-codec-socks", "4.1.135.Final");
  const lodash = npmPkg("lodash", "4.17.20");
  const pypi = { name: "requests", version: "2.31.0", ecosystem: "PyPI" as const };

  function nettyMock() {
    fetchImpl = async (url: string) => {
      if (url.includes("netty-codec-socks")) return new Response(FIXTURE, { status: 200 });
      if (url.includes("/npm/lodash")) return new Response("not found", { status: 404 });
      throw new Error(`unexpected url ${url}`);
    };
  }

  test("fetches supported coordinates only and caches results", async () => {
    nettyMock();
    const entries = await loadSnykAdvisories([netty, lodash, pypi]);
    expect(fetchCalls).toHaveLength(2); // PyPI coordinate skipped
    expect(entries.length).toBe(1);
    expect(entries[0].id).toBe("CVE-2026-62380");
    expect(entries[0].affected[0].package.name).toBe("io.netty:netty-codec-socks");

    const mavenCache = JSON.parse(fs.readFileSync(path.join(getSnykCacheDir(), "maven", "io.netty_netty-codec-socks.json"), "utf8"));
    expect(mavenCache.entries.length).toBe(1);
    const npmCache = JSON.parse(fs.readFileSync(path.join(getSnykCacheDir(), "npm", "lodash.json"), "utf8"));
    expect(npmCache.entries).toEqual([]); // 404 cached as empty
  });

  test("reuses fresh cache without fetching", async () => {
    nettyMock();
    await loadSnykAdvisories([netty, lodash]);
    fetchCalls = [];
    const entries = await loadSnykAdvisories([netty, lodash]);
    expect(fetchCalls).toHaveLength(0);
    expect(entries.length).toBe(1);
  });

  test("forceRefresh re-fetches despite a fresh cache", async () => {
    nettyMock();
    await loadSnykAdvisories([netty]);
    fetchCalls = [];
    await loadSnykAdvisories([netty], { forceRefresh: true });
    expect(fetchCalls).toHaveLength(1);
  });

  test("offline with no cache warns and does not fetch", async () => {
    const warnings: string[] = [];
    fetchImpl = async () => { throw new Error("must not fetch"); };
    const entries = await loadSnykAdvisories([npmPkg("left-pad")], { offline: true, onWarning: (w) => warnings.push(w) });
    expect(entries).toEqual([]);
    expect(fetchCalls).toHaveLength(0);
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("cache missing");
  });

  test("offline with a stale cache serves it without fetching", async () => {
    const file = path.join(getSnykCacheDir(), "npm", "left-pad.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const doc = { fetchedAt: Date.now() - 30 * 24 * 3600 * 1000, entries: [{ id: "CVE-2020-9999", aliases: [], ecosystems: ["npm"], summary: "stale", severity: [], affected: [], links: [] }] };
    fs.writeFileSync(file, JSON.stringify(doc));

    fetchImpl = async () => { throw new Error("must not fetch"); };
    const entries = await loadSnykAdvisories([npmPkg("left-pad")], { offline: true });
    expect(entries.length).toBe(1);
    expect(entries[0].id).toBe("CVE-2020-9999");
    expect(fetchCalls).toHaveLength(0);
  });

  test("online failure falls back to stale cache without warning", async () => {
    const file = path.join(getSnykCacheDir(), "npm", "stale-pkg.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const doc = { fetchedAt: Date.now() - 30 * 24 * 3600 * 1000, entries: [{ id: "CVE-2020-8888", aliases: [], ecosystems: ["npm"], summary: "stale", severity: [], affected: [], links: [] }] };
    fs.writeFileSync(file, JSON.stringify(doc));

    fetchImpl = async () => { throw new Error("network down"); };
    const warnings: string[] = [];
    const entries = await loadSnykAdvisories([npmPkg("stale-pkg")], { onWarning: (w) => warnings.push(w) });
    expect(entries.length).toBe(1);
    expect(entries[0].id).toBe("CVE-2020-8888");
    expect(warnings).toHaveLength(0);
  }, 30000);

  test("online failure with no cache warns and returns empty", async () => {
    fetchImpl = async () => { throw new Error("network down"); };
    const warnings: string[] = [];
    const entries = await loadSnykAdvisories([npmPkg("never-seen")], { onWarning: (w) => warnings.push(w) });
    expect(entries).toEqual([]);
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("unavailable for 1 of 1");
  }, 30000);

  test("no supported coordinates → no fetch, no entries", async () => {
    fetchImpl = async () => { throw new Error("must not fetch"); };
    const entries = await loadSnykAdvisories([pypi]);
    expect(entries).toEqual([]);
    expect(fetchCalls).toHaveLength(0);
  });

  test("lowercase maven ecosystem (as emitted by the parsers) still produces a coordinate", async () => {
    fetchImpl = async () => new Response("", { status: 404 });
    const lowerMaven = { name: "org.example:lower-pkg", version: "1.0.0", ecosystem: "maven" as const };
    const entries = await loadSnykAdvisories([lowerMaven]);
    expect(entries).toEqual([]); // 404 → cached empty
    expect(fetchCalls).toHaveLength(1);
    expect(fetchCalls[0]).toBe("https://security.snyk.io/package/maven/org.example%3Alower-pkg");
  });

  test("maven coordinate case is folded for the url and the cache file", async () => {
    fetchImpl = async () => new Response("", { status: 404 });
    await loadSnykAdvisories([
      { name: "Org.Example:Mixed-Case", version: "1.0.0", ecosystem: "maven" },
      { name: "org.example:mixed-case", version: "1.0.0", ecosystem: "Maven" },
    ]);
    expect(fetchCalls).toEqual(["https://security.snyk.io/package/maven/org.example%3Amixed-case"]);
    expect(fs.existsSync(path.join(getSnykCacheDir(), "maven", "org.example_mixed-case.json"))).toBe(true);
  });

  test("same CVE on two packages keeps both affected blocks", async () => {
    const page = (fixed: string) => `<script id="__NUXT_DATA__">${JSON.stringify([{
      vulnerabilities: [{
        id: "SNYK-JAVA-DEMO-1",
        title: "Shared CVE",
        severity: "high",
        affectedVersions: [{ min: null, max: { version: fixed, inclusive: false } }],
        identifiers: { CVE: ["CVE-2026-9999"], GHSA: ["GHSA-demo-demo-demo"] },
      }],
    }])}</script>`;
    fetchImpl = async (url: string) => {
      if (url.includes("demo-a")) return new Response(page("1.2.0"), { status: 200 });
      if (url.includes("demo-b")) return new Response(page("3.4.0"), { status: 200 });
      throw new Error(url);
    };
    const entries = await loadSnykAdvisories([
      { name: "org.demo:demo-a", version: "1.0.0", ecosystem: "maven" },
      { name: "org.demo:demo-b", version: "1.0.0", ecosystem: "maven" },
    ]);
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe("CVE-2026-9999");
    const names = entries[0].affected.map((a) => a.package?.name).sort();
    expect(names).toEqual(["org.demo:demo-a", "org.demo:demo-b"]);
    const encoded = JSON.stringify(entries[0].affected);
    expect(encoded).toContain("1.2.0");
    expect(encoded).toContain("3.4.0");
  });

  test("payload without a vulnerabilities array is not cached as empty", async () => {
    fetchImpl = async () => new Response(`<script id="__NUXT_DATA__">${JSON.stringify([{ description: "x" }])}</script>`, { status: 200 });
    const warnings: string[] = [];
    let incomplete = false;
    const entries = await loadSnykAdvisories([npmPkg("no-key-pkg")], {
      onWarning: (w) => warnings.push(w),
      onIncomplete: () => { incomplete = true; },
    });
    expect(entries).toEqual([]);
    expect(incomplete).toBe(true);
    expect(warnings.length).toBe(1);
    expect(fs.existsSync(path.join(getSnykCacheDir(), "npm", "no-key-pkg.json"))).toBe(false);
  });

  test("payload without a vulnerabilities array does not overwrite a stale cache", async () => {
    const file = path.join(getSnykCacheDir(), "npm", "kept-stale.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({
      fetchedAt: Date.now() - 30 * 24 * 3600 * 1000,
      entries: [{ id: "CVE-KEEP", aliases: [], ecosystems: ["npm"], summary: "keep", severity: [], affected: [], links: [] }],
    }));
    fetchImpl = async () => new Response(`<script id="__NUXT_DATA__">${JSON.stringify([{ description: "x" }])}</script>`, { status: 200 });
    const warnings: string[] = [];
    const entries = await loadSnykAdvisories([npmPkg("kept-stale")], { onWarning: (w) => warnings.push(w) });
    expect(entries.map((e) => e.id)).toEqual(["CVE-KEEP"]);
    expect(warnings).toHaveLength(0);
    expect(JSON.parse(fs.readFileSync(file, "utf8")).entries[0].id).toBe("CVE-KEEP");
  });

  test("malformed cache is treated as a miss and refetched", async () => {
    const file = path.join(getSnykCacheDir(), "npm", "bad-cache.json");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "{not json");
    fetchImpl = async () => new Response(`<script id="__NUXT_DATA__">${JSON.stringify([{ vulnerabilities: [] }])}</script>`, { status: 200 });
    const entries = await loadSnykAdvisories([npmPkg("bad-cache")]);
    expect(fetchCalls).toHaveLength(1);
    expect(entries).toEqual([]);
    expect(JSON.parse(fs.readFileSync(file, "utf8")).entries).toEqual([]);
  });

  test("scan is incomplete when Snyk fails and no cache exists", async () => {
    process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;
    const { writeCacheFile } = await import("../src/lib/osv-cache.ts");
    const { getGhsaSincePath } = await import("../src/lib/github-repo-advisories.ts");
    const { runAutoBumperScan } = await import("../src/scan.ts");
    writeCacheFile("NPM", []);
    writeCacheFile("repo-advisories", []);
    fs.mkdirSync(path.dirname(getGhsaSincePath()), { recursive: true });
    fs.writeFileSync(getGhsaSincePath(), "2020-01-01T00:00:00Z");

    const proj = fs.mkdtempSync(path.join(os.tmpdir(), "snyk-incomplete-"));
    fs.writeFileSync(path.join(proj, "package-lock.json"), JSON.stringify({
      name: "fixture",
      lockfileVersion: 2,
      packages: {
        "": { name: "fixture", version: "1.0.0" },
        "node_modules/snyk-incomplete-pkg": { version: "1.0.0" },
      },
    }));
    fetchImpl = async () => { throw new Error("snyk down"); };
    try {
      const result = await runAutoBumperScan(proj, { quiet: true });
      expect(result.incomplete).toBe(true);
      expect(result.warnings.some((w) => w.includes("Snyk advisories unavailable"))).toBe(true);
    } finally {
      fs.rmSync(proj, { recursive: true, force: true });
    }
  }, 30000);
});
