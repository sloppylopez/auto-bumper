import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { afterAll, afterEach, beforeEach, describe, expect, it, mock } from "bun:test";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-osv-freshness-"));
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;

// Mock the OSV dump download before scan.ts is loaded (module registry is shared across files).
const actualOsvExport = await import("../src/lib/osv-export.ts");
const dumpMock = mock(async (_name: string): Promise<{ entries: unknown[]; etag: string | null }> => ({ entries: [], etag: null }));
mock.module("../src/lib/osv-export.ts", () => ({ ...actualOsvExport, downloadOsvEcosystemDump: dumpMock }));

// Dynamic import (not static): scan.ts freezes its cache dir from AUTO_BUMPER_CACHE_DIR at
// module evaluation. Target the exported DB dir at use-time, never an env-derived path.
const { readCacheEtag, writeCacheEtag } = await import("../src/lib/osv-cache.ts");

const { loadAdvisoriesForEcosystem, getOsvDbDir } = await import("../src/scan.ts");
// Real probe seam (never overridden by module mocks).
const { resetRemoteEtagProbe } = actualOsvExport;

/** Always resolve at use-time — env may differ across test files sharing the module registry. */
const dbDir = () => getOsvDbDir();

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

let realFetch: typeof fetch;

beforeEach(() => {
  resetRemoteEtagProbe();
  fs.rmSync(dbDir(), { recursive: true, force: true });
  dumpMock.mockClear();
  dumpMock.mockResolvedValue({ entries: [], etag: null });
  // Save whatever the previous test file left installed; restore after each case.
  realFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

afterAll(() => {
  delete process.env.AUTO_BUMPER_CACHE_DIR;
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

function fetchWithEtag(etag: string): typeof fetch {
  return (mock(async () => new Response(null, { status: 200, headers: { etag } })) as unknown) as typeof fetch;
}

const failingFetch = mock(async () => {
  throw new Error("network disabled in tests");
}) as unknown as typeof fetch;

describe("OSV dump ETag freshness", () => {
  it("uses the cache without downloading when the remote ETag is unchanged", async () => {
    writeGz("Maven", [advisory("GHSA-cached", "io.netty:netty-codec-http3")], 60 * 60 * 1000);
    writeCacheEtag("Maven", '"v1"');
    globalThis.fetch = fetchWithEtag('"v1"');

    const advs = await loadAdvisoriesForEcosystem("maven");

    expect(dumpMock).not.toHaveBeenCalled();
    expect(advs[0].id).toBe("GHSA-cached");
  });

  it("re-downloads and persists the new ETag when the remote dump changed", async () => {
    writeGz("Maven", [advisory("GHSA-old", "io.netty:netty-codec-http3")], 60 * 60 * 1000);
    writeCacheEtag("Maven", '"old"');
    globalThis.fetch = fetchWithEtag('"new"');
    dumpMock.mockResolvedValue({ entries: [advisory("GHSA-new", "io.netty:netty-codec-http3")], etag: '"new"' });

    const advs = await loadAdvisoriesForEcosystem("maven");

    expect(dumpMock).toHaveBeenCalledWith("Maven");
    expect(advs[0].id).toBe("GHSA-new");
    expect(readCacheEtag("Maven")).toBe('"new"');
  });

  it("falls back to a fresh cache when the probe fails", async () => {
    writeGz("Maven", [advisory("GHSA-cached", "io.netty:netty-codec-http3")], 60 * 60 * 1000);
    globalThis.fetch = failingFetch;

    const advs = await loadAdvisoriesForEcosystem("maven");

    expect(dumpMock).not.toHaveBeenCalled();
    expect(advs[0].id).toBe("GHSA-cached");
  });

  it("refreshes a stale cache when the probe fails", async () => {
    writeGz("Maven", [advisory("GHSA-old", "io.netty:netty-codec-http3")], 8 * DAY);
    globalThis.fetch = failingFetch;
    dumpMock.mockResolvedValue({ entries: [advisory("GHSA-new", "io.netty:netty-codec-http3")], etag: null });

    const advs = await loadAdvisoriesForEcosystem("maven");

    expect(dumpMock).toHaveBeenCalledWith("Maven");
    expect(advs[0].id).toBe("GHSA-new");
  });

  it("never probes the network in offline mode", async () => {
    writeGz("Maven", [advisory("GHSA-cached", "io.netty:netty-codec-http3")], 8 * DAY);
    const fetchSpy = mock(async () => new Response(null, { status: 200 }));
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    const advs = await loadAdvisoriesForEcosystem("maven", null, true);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(dumpMock).not.toHaveBeenCalled();
    expect(advs[0].id).toBe("GHSA-cached");
  });
});
