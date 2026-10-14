import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "bun:test";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-p0-"));
const prevCache = process.env.AUTO_BUMPER_CACHE_DIR;
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;

const { writeCacheFile, readCacheFile } = await import("../src/lib/osv-cache.ts");
const { matchesSemverRange } = await import("../src/lib/matcher.ts");
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
    expect(merged[0].affected[0].ranges).toHaveLength(1);
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
