import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "bun:test";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-p0-"));
const prevCache = process.env.AUTO_BUMPER_CACHE_DIR;
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;

const { writeCacheFile, readCacheFile } = await import("../src/lib/osv-cache.ts");
const { matchVulnerabilities, matchesSemverRange } = await import("../src/lib/matcher.ts");
const { getOsvDbDir } = await import("../src/path.ts");
const { advisoryRichness, mergeAdvisories } = await import("../src/scan.ts");
import type { AdvisoryEntry } from "../src/lib/types.ts";

afterAll(() => {
  if (prevCache === undefined) delete process.env.AUTO_BUMPER_CACHE_DIR;
  else process.env.AUTO_BUMPER_CACHE_DIR = prevCache;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function baseAdv(id: string, extra: Partial<AdvisoryEntry> = {}): AdvisoryEntry {
  return {
    id,
    aliases: [],
    ecosystems: ["npm"],
    summary: "short",
    severity: [],
    affected: [],
    links: [],
    ...extra,
  };
}

describe("mergeAdvisories richness", () => {
  it("replaces stale local with richer same-ID API record", () => {
    const local = baseAdv("GHSA-same", {
      affected: [{ package: { name: "left-pad" }, versions: ["1.0.0"], ranges: [] }],
    });
    const api = baseAdv("GHSA-same", {
      aliases: ["CVE-2024-1"],
      summary: "A much longer summary with real detail",
      affected: [{
        package: { name: "left-pad" },
        versions: ["1.0.0", "1.0.1"],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0.2" }] }],
      }],
      links: [{ url: "https://example.com" }],
    });
    expect(advisoryRichness(api)).toBeGreaterThan(advisoryRichness(local));
    const merged = mergeAdvisories([local], [api]);
    expect(merged).toHaveLength(1);
    expect(merged[0].aliases).toEqual(["CVE-2024-1"]);
    expect(merged[0].affected.some(a => a.ranges?.length === 1)).toBe(true);
  });

  it("keeps local when it is richer than API", () => {
    const local = baseAdv("GHSA-keep", {
      aliases: ["CVE-1", "CVE-2"],
      summary: "Detailed local summary text here",
      affected: [{
        package: { name: "x" },
        versions: ["1"],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2" }] }],
      }],
    });
    const api = baseAdv("GHSA-keep", {
      affected: [{ package: { name: "x" }, versions: [], ranges: [] }],
    });
    const merged = mergeAdvisories([local], [api]);
    expect(merged[0].aliases).toEqual(["CVE-1", "CVE-2"]);
  });

  it("unions affected packages instead of letting the richer record delete one", () => {
    const osv = baseAdv("CVE-2026-1", {
      aliases: ["GHSA-a", "GHSA-b", "GHSA-c"],
      summary: "A long OSV summary that is definitely richer than the snyk one",
      links: [{ url: "https://osv.dev/x" }, { url: "https://nvd.example/x" }],
      severity: [{ type: "CVSS_V3_1", score: "9.8" }],
      affected: [
        { package: { name: "org.demo:demo-a", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }] },
        { package: { name: "org.demo:demo-b", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }] },
      ],
    });
    const snyk = baseAdv("CVE-2026-1", {
      aliases: ["SNYK-1"],
      summary: "short",
      severity: [{ type: "CVSS_V3_1", score: "7.5" }],
      affected: [
        { package: { name: "org.demo:demo-a", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] },
      ],
    });
    expect(advisoryRichness(osv)).toBeGreaterThan(advisoryRichness(snyk));
    const merged = mergeAdvisories([osv], [snyk]);
    expect(merged).toHaveLength(1);
    const names = [...new Set(merged[0].affected.map(a => a.package?.name))].sort();
    expect(names).toEqual(["org.demo:demo-a", "org.demo:demo-b"]);
    const demoA = merged[0].affected.filter(a => a.package?.name === "org.demo:demo-a");
    const encoded = JSON.stringify(demoA.map(a => a.ranges));
    expect(demoA).toHaveLength(2);
    expect(encoded).toContain("1.2.3");
    expect(encoded).toContain("1.0.0");
    expect(merged[0].aliases).toContain("SNYK-1");
    expect(merged[0].aliases).toContain("GHSA-a");
    expect(merged[0].severity.map(s => s.score)).toEqual(["9.8", "7.5"]);
  });

  it("keeps GHSA version-list authority separate from newer range-only records", () => {
    const packageName = "org.example:library";
    const older = baseAdv("GHSA-authority", {
      ecosystems: ["Maven"],
      affected: [{ package: { name: packageName, ecosystem: "Maven" }, versions: ["1.0.0"], ranges: [] }],
    });
    const newer = baseAdv("GHSA-authority", {
      ecosystems: ["Maven"],
      affected: [{
        package: { name: packageName, ecosystem: "Maven" },
        versions: [],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0.0" }, { fixed: "2.5.0" }] }],
      }],
    });
    const merged = mergeAdvisories([older], [newer]);
    expect(merged[0].affected).toHaveLength(2);
    expect(matchVulnerabilities(
      [{ ecosystem: "maven", name: packageName, version: "2.1.0", manifestPath: "pom.xml" }],
      merged,
    )).toHaveLength(1);
  });

  it("preserves independent and representation ranges when merging", () => {
    const primary = baseAdv("CVE-independent-window", {
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.example:window", ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.0.0" }, { fixed: "4.1.0" }] }],
      }],
    });
    const otherWindow = baseAdv("CVE-independent-window", {
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.example:window", ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }] }],
      }],
    });
    const merged = mergeAdvisories([primary], [otherWindow]);
    expect(merged[0].affected).toHaveLength(2);
    expect(matchVulnerabilities(
      [{ ecosystem: "maven", name: "org.example:window", version: "3.5.0", manifestPath: "pom.xml" }],
      merged,
    )).toHaveLength(1);

    const semver = mergeAdvisories(
      [baseAdv("CVE-representation", {
        affected: [{
          package: { name: "rep-lib", ecosystem: "npm" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.5.0" }] }],
        }],
      })],
      [baseAdv("CVE-representation", {
        affected: [{
          package: { name: "rep-lib", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", representations: [{ type: "SEMVER", range: ">=3.0.0" }] }],
        }],
      })],
    );
    expect(matchVulnerabilities(
      [{ ecosystem: "npm", name: "rep-lib", version: "3.1.0", manifestPath: "package-lock.json" }],
      semver,
    )).toHaveLength(1);
  });
});

describe("matchesSemverRange fail-closed", () => {
  it("matches supported operators", () => {
    expect(matchesSemverRange("1.5.0", ">=1.0.0,<2.0.0")).toBe(true);
    expect(matchesSemverRange("2.0.0", ">=1.0.0,<2.0.0")).toBe(false);
  });

  it("rejects unknown operators instead of treating as match", () => {
    expect(matchesSemverRange("1.2.3", "^1.0.0")).toBe(false);
    expect(matchesSemverRange("1.2.3", "~1.2.0")).toBe(false);
    expect(matchesSemverRange("1.2.3", ">=1.0.0 || <0")).toBe(false);
  });
});

describe("atomic cache write / corrupt soft-fail", () => {
  it("writeCacheFile round-trips", () => {
    const data = [baseAdv("GHSA-atomic")];
    writeCacheFile("P0ATOMIC", data);
    expect(readCacheFile("P0ATOMIC")?.[0]?.id).toBe("GHSA-atomic");
  });

  it("corrupt gzip returns null (cache miss)", () => {
    const dir = getOsvDbDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "P0CORRUPT.json.gz"), Buffer.from("not-gzip"));
    expect(readCacheFile("P0CORRUPT")).toBeNull();
  });

  it("corrupt json returns null", () => {
    const dir = getOsvDbDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "P0BADJSON.json"), "{not json");
    expect(readCacheFile("P0BADJSON")).toBeNull();
  });
});
