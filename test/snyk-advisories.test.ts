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

  test("no CVE → SNYK id is the id; unknown severity defaults to medium score", () => {
    const e = snykVulnToOsv({ id: "SNYK-JAVA-ORGECLIPSEPARSSON-17817925", severity: "high", affectedVersions: [] }, "org.glassfish:parsson", "Maven")!;
    expect(e.id).toBe("SNYK-JAVA-ORGECLIPSEPARSSON-17817925");
    expect(e.aliases).toEqual(["SNYK-JAVA-ORGECLIPSEPARSSON-17817925"]);
    expect(e.severity).toEqual([{ type: "CVSS_V3_1", score: "7.5" }]);
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
});
