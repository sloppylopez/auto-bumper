import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-cache-fresh-"));
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;

// Mock the OSV dump download before scan.ts is loaded.
const actualOsvExport = await import("../src/lib/osv-export.ts");
const dumpMock = mock(async (_name: string): Promise<{ entries: unknown[]; etag: string | null }> => ({ entries: [], etag: null }));
mock.module("../src/lib/osv-export.ts", () => ({ ...actualOsvExport, downloadOsvEcosystemDump: dumpMock }));
// Stub the live fetch so online-mode scans (repo advisories, dump downloads) stay hermetic.
const actualFetchRetry = await import("../src/lib/fetch-retry.ts");
const fetchMock = mock(async () => new Response("{}", { status: 404 }));
mock.module("../src/lib/fetch-retry.ts", () => ({ ...actualFetchRetry, fetchWithRetry: fetchMock }));
// Raw fetch is used by the ETag freshness probe (HEAD); disable it so online runs stay hermetic.
const realFetch = globalThis.fetch;
beforeAll(() => {
  globalThis.fetch = (async () => { throw new Error("network disabled in tests"); }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

// Dynamic import (not static): scan.ts freezes its cache dir from AUTO_BUMPER_CACHE_DIR at
// module evaluation. bun test shares one module registry across files, so whichever file imports
// scan.ts first wins — always target the exported DB_DIR, never an env-derived path.
const { getOsvDbDir, readCacheFile, runAutoBumperScan } = await import("../src/scan.ts");
/** Always resolve at use-time — env may differ across test files sharing the module registry. */
const dbDir = () => getOsvDbDir();

afterAll(() => {
  delete process.env.AUTO_BUMPER_CACHE_DIR;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

beforeEach(() => {
  // Other test files may overwrite the cache env; pin ours before every case.
  process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;
});

const DAY = 24 * 60 * 60 * 1000;

function advisory(id: string, pkgName: string) {
  return {
    id,
    aliases: [],
    ecosystems: ["Maven"],
    summary: `test advisory ${id}`,
    severity: [{ type: "CVSS_V3_1", score: "7.5" }],
    affected: [
      {
        package: { name: pkgName, ecosystem: "Maven" },
        versions: [],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "999" }] }],
      },
    ],
    links: [],
  };
}

function writeGz(osvName: string, data: unknown[], ageMs: number): void {
  const dir = dbDir();
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, `${osvName}.json.gz`);
  fs.writeFileSync(p, zlib.gzipSync(JSON.stringify(data)));
  const t = new Date(Date.now() - ageMs);
  fs.utimesSync(p, t, t);
}

function writeJson(osvName: string, data: unknown[], ageMs: number): void {
  const dir = dbDir();
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, `${osvName}.json`);
  fs.writeFileSync(p, JSON.stringify(data));
  const t = new Date(Date.now() - ageMs);
  fs.utimesSync(p, t, t);
}

function writeProj(depVersion: string): string {
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
      <version>${depVersion}</version>
    </dependency>
  </dependencies>
</project>
`,
  );
  return proj;
}

// Hide system mvn so parsePomXml takes the direct-parser path deterministically
// (the `mvn dependency:tree` probe adds seconds and depends on a local Maven install).
const NO_MVN_PATH = process.platform === "win32" ? "C:\\Windows" : "/nonexistent";

async function scanWithoutMvn(proj: string, opts: { quiet: boolean; offline: boolean }) {
  const savedPath = process.env.PATH;
  process.env.PATH = NO_MVN_PATH;
  try {
    return await runAutoBumperScan(proj, opts);
  } finally {
    process.env.PATH = savedPath;
  }
}

describe("readCacheFile .gz/.json shadowing", () => {
  it("prefers the newer plain .json over a stale .gz", () => {
    writeGz("SHADOWTEST", [advisory("GHSA-old-gz", "x:y")], 2 * DAY);
    writeJson("SHADOWTEST", [advisory("GHSA-new-json", "x:y")], 60_000);
    expect(readCacheFile("SHADOWTEST")?.[0]?.id).toBe("GHSA-new-json");
  });

  it("prefers the newer .gz over a stale plain .json", () => {
    writeJson("SHADOWTEST2", [advisory("GHSA-old-json", "x:y")], 2 * DAY);
    writeGz("SHADOWTEST2", [advisory("GHSA-new-gz", "x:y")], 60_000);
    expect(readCacheFile("SHADOWTEST2")?.[0]?.id).toBe("GHSA-new-gz");
  });
});

describe("scan cache auto-refresh", () => {
  it("refreshes a stale OSV cache instead of using it", async () => {
    const proj = writeProj("4.2.17.Final");
    writeGz("Maven", [advisory("GHSA-stale-hit", "io.netty:netty-codec-http3")], 8 * DAY);
    dumpMock.mockClear();
    dumpMock.mockResolvedValue({ entries: [advisory("GHSA-fresh-miss", "com.example:unrelated-lib")], etag: null });

    const result = await scanWithoutMvn(proj, { quiet: true, offline: false });

    expect(dumpMock).toHaveBeenCalledWith("Maven");
    // The stale record flagged the package; the fresh dump does not. Stale data must not leak through.
    expect(result.findings).toHaveLength(0);
  });

  it("uses a stale cache without re-downloading when offline", async () => {
    const proj = writeProj("4.2.17.Final");
    writeGz("Maven", [advisory("GHSA-stale-offline-hit", "io.netty:netty-codec-http3")], 8 * DAY);
    dumpMock.mockClear();
    dumpMock.mockImplementation(async () => {
      throw new Error("download must not run in offline mode");
    });

    const result = await scanWithoutMvn(proj, { quiet: true, offline: true });

    expect(dumpMock).not.toHaveBeenCalled();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("GHSA-stale-offline-hit");
  });

  it("uses a fresh cache without re-downloading", async () => {
    const proj = writeProj("4.2.17.Final");
    writeGz("Maven", [advisory("GHSA-fresh-hit", "io.netty:netty-codec-http3")], 60 * 60 * 1000);
    dumpMock.mockClear();
    dumpMock.mockImplementation(async () => {
      throw new Error("download must not run for a fresh cache");
    });

    const result = await scanWithoutMvn(proj, { quiet: true, offline: true });

    expect(dumpMock).not.toHaveBeenCalled();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("GHSA-fresh-hit");
  });
});
