import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { afterAll, describe, expect, it, mock } from "bun:test";
// Type-only: erased at compile time, so this does not trigger scan.ts evaluation early.
import type { ScanResult } from "../src/scan.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-suppl-"));
process.env.AUTO_BUMPER_CACHE_DIR = tmpRoot;
delete process.env.AUTO_BUMPER_SUPPLEMENTAL;

// Mock the OSV bulk dump (empty): findings under test must come from local advisories / repo advisories only.
// Exception to ts-no-dynamic-import (module-loading boundary): mock.module must install the dump stub before
// scan.ts's import graph evaluates, and both modules freeze paths derived from AUTO_BUMPER_CACHE_DIR at
// evaluation time — so the env var above must be set first.
const actualOsvExport = await import("../src/lib/osv-export.ts");
const dumpMock = mock(async (_name: string): Promise<{ entries: unknown[]; etag: string | null }> => ({ entries: [], etag: null }));
mock.module("../src/lib/osv-export.ts", () => ({ ...actualOsvExport, downloadOsvEcosystemDump: dumpMock }));

// Dynamic imports (not static): scan.ts freezes paths derived from AUTO_BUMPER_CACHE_DIR at module evaluation.
const { runAutoBumperScan, supplementalDisabled, getOsvDbDir } = await import("../src/scan.ts");

const originalFetch = globalThis.fetch;

afterAll(() => {
  globalThis.fetch = originalFetch;
});

function withEnv(value: string | undefined, fn: () => Promise<void>): Promise<void> {
  const saved = process.env.AUTO_BUMPER_SUPPLEMENTAL;
  if (value === undefined) delete process.env.AUTO_BUMPER_SUPPLEMENTAL;
  else process.env.AUTO_BUMPER_SUPPLEMENTAL = value;
  return fn().finally(() => {
    if (saved === undefined) delete process.env.AUTO_BUMPER_SUPPLEMENTAL;
    else process.env.AUTO_BUMPER_SUPPLEMENTAL = saved;
  });
}

/**
 * Maven project with a netty dep (GHSA-flaggable, absent from the mocked dump) and a log4j-core dep
 * (would trigger the orphan-CVE bridge if supplemental sources were active).
 */
function writeProject(dir: string, localAdvisoryId: string | null): void {
  fs.mkdirSync(path.join(dir, "local-advisories"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "pom.xml"),
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
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.20.0</version>
    </dependency>
  </dependencies>
</project>
`,
  );
  if (localAdvisoryId) {
    fs.writeFileSync(
      path.join(dir, "local-advisories", "Maven.json"),
      JSON.stringify([
        {
          id: localAdvisoryId,
          aliases: [localAdvisoryId],
          ecosystems: ["Maven"],
          summary: "test advisory",
          severity: [{ type: "CVSS_V3_1", score: "5.0" }],
          affected: [{ package: { name: "io.netty:netty-codec-http3", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.2.18.Final" }] }] }],
        },
      ]),
    );
  }
}

function ghSaOnlyFetch(hits: string[]) {
  // api.github.com answers with one GHSA; everything else (GCS etag probe, OSV API) → 404.
  return mock(async (url: string | URL) => {
    const u = String(url);
    hits.push(u);
    if (u.includes("api.github.com")) {
      return new Response(
        JSON.stringify([
          {
            ghsa_id: "GHSA-q9pg-8h3j-8hvm",
            cve_id: null,
            severity: "medium",
            summary: "test GHSA",
            html_url: "https://github.com/netty/netty/security/advisories/GHSA-q9pg-8h3j-8hvm",
            vulnerabilities: [
              { package: { ecosystem: "Maven", name: "io.netty:netty-codec-http3" }, vulnerable_version_range: ">= 4.2.0.Final, <= 4.2.17.Final", patched_versions: "4.2.18.Final" },
            ],
          },
        ]),
        { status: 200 },
      );
    }
    return new Response(null, { status: 404 });
  });
}

describe("supplementalDisabled", () => {
  it("treats off/0/false in any case as disabled", async () => {
    for (const v of ["off", "OFF", "Off", "0", "false", "FALSE", "False"]) {
      await withEnv(v, async () => {
        expect(supplementalDisabled()).toBe(true);
      });
    }
  });

  it("treats unset and other values as enabled", async () => {
    for (const v of [undefined, "on", "1", "true", "maybe", ""]) {
      await withEnv(v, async () => {
        expect(supplementalDisabled()).toBe(false);
      });
    }
  });
});

describe("scan with AUTO_BUMPER_SUPPLEMENTAL=off", () => {
  it("attempts no supplemental fetch and still reports locally-vendored findings", async () => {
    await withEnv("off", async () => {
      const proj = path.join(tmpRoot, "proj-off");
      writeProject(proj, "CVE-2026-90001");

      const hits: string[] = [];
      globalThis.fetch = ghSaOnlyFetch(hits);
      let result: ScanResult;
      try {
        result = await runAutoBumperScan(proj, { quiet: true });
      } finally {
        globalThis.fetch = originalFetch;
      }

      // Neither supplemental source may be touched.
      expect(hits.some((u) => u.includes("api.github.com"))).toBe(false);
      expect(hits.some((u) => u.includes("api.osv.dev"))).toBe(false);

      // Findings still served from dump + local advisories (the project-vendored entry must match).
      const local = result.findings.find((f) => f.id === "CVE-2026-90001");
      expect(local).toBeDefined();
      expect(local?.packageName).toBe("io.netty:netty-codec-http3");
      // No degraded-advisory warning for a source we intentionally skipped.
      expect(result.warnings.some((w) => w.includes("GitHub Maven advisories unavailable"))).toBe(false);
    });
  }, 20000);

  it("value 0 behaves the same as off", async () => {
    await withEnv("0", async () => {
      const proj = path.join(tmpRoot, "proj-zero");
      writeProject(proj, null);

      const hits: string[] = [];
      globalThis.fetch = ghSaOnlyFetch(hits);
      let result: ScanResult;
      try {
        result = await runAutoBumperScan(proj, { quiet: true });
      } finally {
        globalThis.fetch = originalFetch;
      }

      expect(hits.some((u) => u.includes("api.github.com"))).toBe(false);
      // GHSA-only advisory must NOT appear when supplemental is off.
      expect(result.findings.some((f) => f.id === "GHSA-q9pg-8h3j-8hvm")).toBe(false);
    });
  }, 20000);
});

describe("scan with AUTO_BUMPER_SUPPLEMENTAL unset", () => {
  it("keeps current behavior: repo advisories are loaded and matched", async () => {
    await withEnv(undefined, async () => {
      const proj = path.join(tmpRoot, "proj-unset");
      writeProject(proj, null);

      // Seed a fresh repo-advisories cache in the live env dir so this test stays hermetic: earlier files
      // may have permanently mocked fetch-retry (mock.module is process-wide), and scan.ts's frozen DB_DIR
      // may point at another file's tmpRoot. Serving from a warm cache is the same production path an
      // incremental refresh uses, so "repo advisories are loaded and matched" holds without any network.
      const dbDir = getOsvDbDir();
      fs.mkdirSync(dbDir, { recursive: true });
      const entry = {
        id: "GHSA-q9pg-8h3j-8hvm",
        aliases: ["CVE-2026-100000"],
        ecosystems: ["Maven"],
        summary: "test GHSA",
        severity: [{ type: "CVSS_V3_1", score: "5.0" }],
        affected: [
          { package: { name: "io.netty:netty-codec-http3", ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.2.18.Final" }] }] },
        ],
      };
      fs.writeFileSync(path.join(dbDir, "repo-advisories.json.gz"), zlib.gzipSync(JSON.stringify([entry])));
      // A complete sync also records its cursor; without it the cache counts as a partial bootstrap and
      // loadRepoAdvisories attempts a re-sync.
      fs.writeFileSync(path.join(dbDir, "repo-advisories.since"), "2026-01-01T00:00:00Z");

      const result = await runAutoBumperScan(proj, { quiet: true });
      expect(result.findings.some((f) => f.id === "GHSA-q9pg-8h3j-8hvm")).toBe(true);
      // No degraded-advisory warning for a source we intentionally kept.
      expect(result.warnings.some((w) => w.includes("GitHub Maven advisories"))).toBe(false);
    });
  }, 20000);
});
