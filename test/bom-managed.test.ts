import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { computeProtectedPins, fetchBomManagedVersions, parseBomManagedVersions } from "../src/lib/bom-managed.ts";
import { applyBumps } from "../src/lib/gradle-editor.ts";
import type { AdvisoryEntry } from "../src/lib/types.ts";

function depEntry(group: string, artifact: string, version: string, extra = ""): string {
  return [
    "      <dependency>",
    `        <groupId>${group}</groupId>`,
    `        <artifactId>${artifact}</artifactId>`,
    `        <version>${version}</version>`,
    extra,
    "      </dependency>",
  ].filter(Boolean).join("\n");
}

const BOM_POM = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  "<project>",
  "  <modelVersion>4.0.0</modelVersion>",
  "  <groupId>io.quarkus.platform</groupId>",
  "  <artifactId>quarkus-bom</artifactId>",
  "  <version>3.33.4.1</version>",
  "  <packaging>pom</packaging>",
  "  <properties>",
  "    <netty.version>4.1.139.Final</netty.version>",
  "    <jackson.version>2.19.2</jackson.version>",
  "    <nested.version>${jackson.version}</nested.version>",
  "  </properties>",
  "  <dependencyManagement>",
  "    <dependencies>",
  depEntry("io.netty", "netty-codec-http2", "${netty.version}"),
  depEntry("com.fasterxml.jackson.core", "jackson-databind", "${jackson.version}"),
  depEntry("org.example", "nested-prop-lib", "${nested.version}"),
  "    </dependencies>",
  "  </dependencyManagement>",
  "</project>",
].join("\n");

describe("parseBomManagedVersions", () => {
  it("resolves literal and property versions into group:artifact keys", () => {
    const map = parseBomManagedVersions(BOM_POM);
    expect(map.get("io.netty:netty-codec-http2")).toBe("4.1.139.Final");
    expect(map.get("com.fasterxml.jackson.core:jackson-databind")).toBe("2.19.2");
  });

  it("resolves nested property references", () => {
    const map = parseBomManagedVersions(BOM_POM);
    expect(map.get("org.example:nested-prop-lib")).toBe("2.19.2");
  });

  it("skips import-scoped entries (nested BOMs)", () => {
    const pom = [
      "<project>",
      "  <dependencyManagement>",
      "    <dependencies>",
      depEntry("io.spring.boot", "spring-boot-dependencies", "3.5.0", "        <type>pom</type>\n        <scope>import</scope>"),
      "    </dependencies>",
      "  </dependencyManagement>",
      "</project>",
    ].join("\n");
    expect(parseBomManagedVersions(pom).size).toBe(0);
  });

  it("skips entries with unresolvable property versions", () => {
    const pom = [
      "<project>",
      "  <dependencyManagement>",
      "    <dependencies>",
      depEntry("org.example", "missing-prop-lib", "${does.not.exist}"),
      "    </dependencies>",
      "  </dependencyManagement>",
      "</project>",
    ].join("\n");
    expect(parseBomManagedVersions(pom).size).toBe(0);
  });

  it("skips inactive profile dependency management and profile-only properties", () => {
    const pom = [
      "<project>",
      "  <profiles>",
      "    <profile>",
      "      <properties><profile.version>9.9.9</profile.version></properties>",
      "      <dependencyManagement>",
      "        <dependencies>",
      depEntry("org.example", "profile-only-lib", "${profile.version}"),
      "        </dependencies>",
      "      </dependencyManagement>",
      "    </profile>",
      "  </profiles>",
      "</project>",
    ].join("\n");
    expect(parseBomManagedVersions(pom).size).toBe(0);
  });

  it("skips cyclic properties that remain unresolved after the resolution limit", () => {
    const pom = [
      "<project>",
      "  <properties>",
      "    <a>${b}</a>",
      "    <b>${a}</b>",
      "  </properties>",
      "  <dependencyManagement><dependencies>",
      depEntry("org.example", "cyclic-prop-lib", "${a}"),
      "  </dependencies></dependencyManagement>",
      "</project>",
    ].join("\n");
    expect(parseBomManagedVersions(pom).size).toBe(0);
  });

  it("keeps the first declaration when a coordinate appears in multiple sections", () => {
    const pom = [
      "<project>",
      "  <dependencyManagement>",
      "    <dependencies>",
      depEntry("org.example", "dup-lib", "1.0.0"),
      "    </dependencies>",
      "  </dependencyManagement>",
      "  <profiles>",
      "    <profile>",
      "      <dependencyManagement>",
      "        <dependencies>",
      depEntry("org.example", "dup-lib", "2.0.0"),
      "        </dependencies>",
      "      </dependencyManagement>",
      "    </profile>",
      "  </profiles>",
      "</project>",
    ].join("\n");
    const map = parseBomManagedVersions(pom);
    expect(map.get("org.example:dup-lib")).toBe("1.0.0");
  });

  it("returns an empty map for a POM without dependencyManagement", () => {
    expect(parseBomManagedVersions("<project><groupId>x</groupId></project>").size).toBe(0);
  });
});

describe("fetchBomManagedVersions", () => {
  const MANIFEST = [
    "plugins { id 'java' }",
    "repositories {",
    '    maven { url "https://repo.internal.example/m2" }',
    "    mavenCentral()",
    "}",
  ].join("\n");

  function cacheFile(cacheDir: string): string {
    return path.join(cacheDir, "db", "bom", "io.quarkus.platform__quarkus-bom__3.33.4.1.json");
  }

  async function withTempCache(run: (cacheDir: string, manifestPath: string) => Promise<void>): Promise<void> {
    const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-bom-cache-"));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-bom-manifest-"));
    const manifestPath = path.join(dir, "build.gradle");
    fs.writeFileSync(manifestPath, MANIFEST, "utf-8");
    const prev = process.env.AUTO_BUMPER_CACHE_DIR;
    process.env.AUTO_BUMPER_CACHE_DIR = cacheDir;
    try {
      await run(cacheDir, manifestPath);
    } finally {
      if (prev === undefined) delete process.env.AUTO_BUMPER_CACHE_DIR;
      else process.env.AUTO_BUMPER_CACHE_DIR = prev;
      fs.rmSync(cacheDir, { recursive: true, force: true });
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  function stubFetch(handler: (url: string) => Response | Promise<Response>): () => void {
    const realFetch = globalThis.fetch;
    globalThis.fetch = ((url: RequestInfo | URL) => Promise.resolve(handler(String(url)))) as typeof globalThis.fetch;
    return () => { globalThis.fetch = realFetch; };
  }

  it("fetches the BOM POM, parses managed versions, and caches the result", async () => {
    await withTempCache(async (cacheDir, manifestPath) => {
      let fetches = 0;
      const restore = stubFetch(url => {
        fetches++;
        if (url.includes("repo.internal.example")) return new Response(null, { status: 500 });
        return new Response(BOM_POM, { status: 200 });
      });
      try {
        const map = await fetchBomManagedVersions(manifestPath, "io.quarkus.platform", "quarkus-bom", "3.33.4.1");
        expect(map).not.toBeNull();
        expect(map!.get("io.netty:netty-codec-http2")).toBe("4.1.139.Final");
        expect(fetches).toBe(2); // internal repo failed, Maven Central succeeded
        expect(fs.existsSync(cacheFile(cacheDir))).toBe(true);
      } finally {
        restore();
      }
    });
  });

  it("returns null without caching when no repository serves the BOM POM", async () => {
    await withTempCache(async (cacheDir, manifestPath) => {
      const restore = stubFetch(() => new Response(null, { status: 500 }));
      try {
        const map = await fetchBomManagedVersions(manifestPath, "io.quarkus.platform", "quarkus-bom", "3.33.4.1");
        expect(map).toBeNull();
        expect(fs.existsSync(cacheFile(cacheDir))).toBe(false);
      } finally {
        restore();
      }
    });
  });

  it("serves repeat lookups from the cache without fetching", async () => {
    await withTempCache(async (_cacheDir, manifestPath) => {
      let fetches = 0;
      const restore = stubFetch(() => {
        fetches++;
        return new Response(BOM_POM, { status: 200 });
      });
      try {
        const first = await fetchBomManagedVersions(manifestPath, "io.quarkus.platform", "quarkus-bom", "3.33.4.1");
        expect(first).not.toBeNull();
        expect(fetches).toBeGreaterThan(0);

        fetches = 0;
        globalThis.fetch = (() => Promise.reject(new Error("network disabled"))) as typeof globalThis.fetch;
        const second = await fetchBomManagedVersions(manifestPath, "io.quarkus.platform", "quarkus-bom", "3.33.4.1");
        expect(second).not.toBeNull();
        expect(second!.get("com.fasterxml.jackson.core:jackson-databind")).toBe("2.19.2");
        expect(fetches).toBe(0); // cache hit — no network
      } finally {
        restore();
      }
    });
  });
  it("does not cache a POM without managed versions", async () => {
    await withTempCache(async (cacheDir, manifestPath) => {
      const restore = stubFetch(() => new Response("<project></project>", { status: 200 }));
      try {
        const map = await fetchBomManagedVersions(manifestPath, "io.quarkus.platform", "quarkus-bom", "3.33.4.1");
        expect(map).toBeNull();
        expect(fs.existsSync(cacheFile(cacheDir))).toBe(false);
      } finally {
        restore();
      }
    });
  });
});

function withTempGradle(content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-bom-"));
  const filePath = path.join(dir, "build.gradle");
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const JAXB_CORE = "org.glassfish.jaxb:jaxb-core";

function jaxbAdvisory(introduced: string): AdvisoryEntry {
  return {
    id: "CVE-2026-92877",
    aliases: ["CVE-2026-92877"],
    ecosystems: ["Maven"],
    summary: "test vulnerability in jaxb-core",
    severity: [],
    affected: [{
      package: { name: JAXB_CORE, ecosystem: "Maven" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced }] }],
    }],
    links: [],
  };
}

describe("computeProtectedPins", () => {
  const bomMap = new Map<string, string>([[JAXB_CORE, "4.0.8"]]);

  function seedEscapePin(filePath: string): void {
    applyBumps(filePath, [{ packageName: JAXB_CORE, targetVersion: "3.0.2", because: ["CVE-2026-92877"], isDowngrade: true }]);
  }

  it("protects a downgrade escape while the BOM-managed version is still affected", () => {
    withTempGradle(`dependencies {\n    implementation "org.slf4j:slf4j-api:2.0.16"\n}\n`, filePath => {
      seedEscapePin(filePath);

      const protectedPins = computeProtectedPins(fs.readFileSync(filePath, "utf-8"), bomMap, [jaxbAdvisory("4.0.0-M4")]);
      expect(protectedPins.get(JAXB_CORE)).toEqual({ packageName: JAXB_CORE, version: "3.0.2", bomVersion: "4.0.8" });
    });
  });

  it("does not protect a pin when the BOM-managed version is clean", () => {
    withTempGradle(`dependencies {\n    implementation "org.slf4j:slf4j-api:2.0.16"\n}\n`, filePath => {
      seedEscapePin(filePath);

      const protectedPins = computeProtectedPins(fs.readFileSync(filePath, "utf-8"), bomMap, [jaxbAdvisory("9.0.0")]);
      expect(protectedPins.size).toBe(0);
    });
  });

  it("does not protect a pin that is itself affected", () => {
    withTempGradle(`dependencies {\n    implementation "org.slf4j:slf4j-api:2.0.16"\n}\n`, filePath => {
      seedEscapePin(filePath);

      const protectedPins = computeProtectedPins(fs.readFileSync(filePath, "utf-8"), bomMap, [jaxbAdvisory("1.0.0")]);
      expect(protectedPins.size).toBe(0);
    });
  });
});
