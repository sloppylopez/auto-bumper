import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "bun:test";
import {
  parseYarnLock,
  parsePnpmLock,
  parseBunLock,
  parseLockfile,
  parseBuildGradleDirect,
  SUPPORTED_LOCKFILE_NAMES,
} from "../src/lib/parse-lockfile.ts";
import { assertValidOsvZip, isZipBuffer, OSV_ZIP_MIN_BYTES } from "../src/lib/osv-export.ts";
import { fetchWithRetry } from "../src/lib/fetch-retry.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-p2-"));

afterAll(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

describe("SUPPORTED_LOCKFILE_NAMES", () => {
  it("includes yarn, pnpm, bun, and build.gradle.kts", () => {
    expect(SUPPORTED_LOCKFILE_NAMES).toContain("yarn.lock");
    expect(SUPPORTED_LOCKFILE_NAMES).toContain("pnpm-lock.yaml");
    expect(SUPPORTED_LOCKFILE_NAMES).toContain("bun.lock");
    expect(SUPPORTED_LOCKFILE_NAMES).toContain("build.gradle.kts");
  });
});

describe("parseYarnLock", () => {
  it("parses classic yarn v1 lock entries including scoped packages", () => {
    const file = path.join(tmpRoot, "yarn.lock");
    fs.writeFileSync(
      file,
      [
        "# yarn lockfile v1",
        "",
        "lodash@^4.17.0:",
        '  version "4.17.21"',
        '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
        "",
        '"@scope/pkg@^1.0.0":',
        '  version "1.2.3"',
        "",
      ].join("\n"),
    );
    const result = parseYarnLock(file);
    const byName = new Map(result.packages.map(p => [p.name, p.version]));
    expect(byName.get("lodash")).toBe("4.17.21");
    expect(byName.get("@scope/pkg")).toBe("1.2.3");
  });
});

describe("parsePnpmLock", () => {
  it("parses packages keys with name@version", () => {
    const file = path.join(tmpRoot, "pnpm-lock.yaml");
    fs.writeFileSync(
      file,
      [
        "lockfileVersion: '9.0'",
        "",
        "packages:",
        "  /lodash@4.17.21:",
        "    resolution: {integrity: sha512-abc}",
        "  /@scope/pkg@1.2.3:",
        "    resolution: {integrity: sha512-def}",
        "",
      ].join("\n"),
    );
    const result = parsePnpmLock(file);
    const byName = new Map(result.packages.map(p => [p.name, p.version]));
    expect(byName.get("lodash")).toBe("4.17.21");
    expect(byName.get("@scope/pkg")).toBe("1.2.3");
  });
});

describe("parseBunLock", () => {
  it("parses packages entries with trailing commas and scoped names", () => {
    const file = path.join(tmpRoot, "bun.lock");
    fs.writeFileSync(
      file,
      [
        "{",
        '  "lockfileVersion": 1,',
        '  "workspaces": {',
        '    "": {',
        '      "dependencies": {',
        '        "lodash": "^4.17.0",',
        "      },",
        "    },",
        "  },",
        '  "packages": {',
        '    "lodash": ["lodash@4.17.21", "", {}, ""],',
        '    "@scope/pkg": ["@scope/pkg@1.2.3", "", {"dependencies": {}}, "sha512-abc=="],',
        '    "three": ["three@0.185.1", "", {}, ""],',
        '    "parent/three": ["three@0.184.0", "", {}, ""],',
        "  },",
        "}",
        "",
      ].join("\n"),
    );
    const result = parseBunLock(file);
    const versions = new Map<string, string[]>();
    for (const p of result.packages) {
      versions.set(p.name, [...(versions.get(p.name) ?? []), p.version]);
    }
    expect(versions.get("lodash")).toEqual(["4.17.21"]);
    expect(versions.get("@scope/pkg")).toEqual(["1.2.3"]);
    // distinct resolved versions of the same package are both kept
    expect([...(versions.get("three") ?? [])].sort()).toEqual(["0.184.0", "0.185.1"]);
  });

  it("skips non-registry resolutions and warns on missing file", () => {
    const file = path.join(tmpRoot, "bun-noreg.lock");
    fs.writeFileSync(
      file,
      [
        "{",
        '  "lockfileVersion": 1,',
        '  "packages": {',
        '    "local": ["link:../local", "", {}, ""],',
        '    "gitdep": ["gitdep@git+https://github.com/x/y.git#abc123", "", {}, ""],',
        '    "ok": ["ok@2.0.0", "", {}, ""],',
        "  },",
        "}",
        "",
      ].join("\n"),
    );
    const result = parseBunLock(file);
    expect(result.packages.map(p => p.name)).toEqual(["ok"]);

    const missing = parseBunLock(path.join(tmpRoot, "does-not-exist.lock"));
    expect(missing.packages).toEqual([]);
    expect(missing.warnings.some(w => w.includes("bun.lock not found"))).toBe(true);
  });

  it("warns when no packages can be parsed", () => {
    const file = path.join(tmpRoot, "bun-empty.lock");
    fs.writeFileSync(file, '{\n  "lockfileVersion": 1,\n  "packages": {},\n}\n');
    const result = parseBunLock(file);
    expect(result.packages).toEqual([]);
    expect(result.warnings.some(w => w.includes("No packages parsed from bun.lock"))).toBe(true);
  });
});

describe("bun.lock npm precedence", () => {
  it("prefers package-lock.json over bun.lock in the same directory", () => {
    const dir = path.join(tmpRoot, "npm-precedence");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "package-lock.json"),
      JSON.stringify({
        name: "precedence",
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.20" } },
      }),
    );
    fs.writeFileSync(
      path.join(dir, "bun.lock"),
      '{\n  "lockfileVersion": 1,\n  "packages": {\n    "lodash": ["lodash@9.9.9", "", {}, ""],\n  },\n}\n',
    );
    const result = parseLockfile(dir);
    const lodash = result.packages.filter(p => p.name === "lodash");
    expect(lodash.map(p => p.version)).toEqual(["4.17.20"]);
  });

  it("uses bun.lock when no other npm lockfile exists", () => {
    const dir = path.join(tmpRoot, "bun-only");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "bun.lock"),
      '{\n  "lockfileVersion": 1,\n  "packages": {\n    "lodash": ["lodash@4.17.21", "", {}, ""],\n  },\n}\n',
    );
    const result = parseLockfile(dir);
    expect(result.packages.map(p => `${p.name}@${p.version}`)).toEqual(["lodash@4.17.21"]);
    expect(result.warnings.some(w => w.includes("No supported lockfile"))).toBe(false);
  });
});

describe("dual Java scan", () => {
  it("parses both pom.xml and build.gradle with a warning", () => {
    const dir = path.join(tmpRoot, "dual-java");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "pom.xml"),
      `<?xml version="1.0"?><project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>t</groupId><artifactId>a</artifactId><version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>`,
    );
    fs.writeFileSync(
      path.join(dir, "build.gradle"),
      `dependencies { implementation "com.google.guava:guava:33.0.0-jre" }\n`,
    );

    const saved = process.env.PATH;
    process.env.PATH = process.platform === "win32" ? "C:\\Windows" : "/nonexistent";
    let result;
    try {
      result = parseLockfile(dir);
    } finally {
      process.env.PATH = saved;
    }

    expect(result.warnings.some(w => w.includes("Both pom.xml and Gradle"))).toBe(true);
    expect(result.packages.some(p => p.name.includes("commons-lang3"))).toBe(true);
    expect(result.packages.some(p => p.name.includes("guava"))).toBe(true);
  });
});

describe("build.gradle.kts direct parse", () => {
  it("resolves Kotlin val and $var versions", () => {
    const file = path.join(tmpRoot, "build.gradle.kts");
    fs.writeFileSync(
      file,
      [
        'val jacksonVersion = "2.21.4"',
        "dependencies {",
        '    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")',
        '    implementation("org.apache.commons:commons-lang3:3.17.0")',
        "}",
        "",
      ].join("\n"),
    );
    const result = parseBuildGradleDirect(file);
    const byName = new Map(result.packages.map(p => [p.name, p.version]));
    expect(byName.get("com.fasterxml.jackson.core:jackson-databind")).toBe("2.21.4");
    expect(byName.get("org.apache.commons:commons-lang3")).toBe("3.17.0");
  });
});

describe("OSV zip integrity", () => {
  it("accepts valid zip magic", () => {
    const buf = Buffer.alloc(OSV_ZIP_MIN_BYTES);
    buf[0] = 0x50;
    buf[1] = 0x4b;
    buf[2] = 0x03;
    buf[3] = 0x04;
    expect(isZipBuffer(buf)).toBe(true);
    expect(() => assertValidOsvZip(buf, { url: "test://x", contentLength: buf.length })).not.toThrow();
  });

  it("rejects bad magic and size mismatch", () => {
    const bad = Buffer.alloc(OSV_ZIP_MIN_BYTES, 0);
    expect(() => assertValidOsvZip(bad, { url: "test://x" })).toThrow(/not a ZIP/);
    const tiny = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
    expect(() => assertValidOsvZip(tiny, { url: "test://x" })).toThrow(/too small/);
  });
});

describe("fetchWithRetry", () => {
  it("retries then succeeds", async () => {
    let calls = 0;
    const original = globalThis.fetch;
    globalThis.fetch = (async () => {
      calls++;
      if (calls < 2) return new Response("nope", { status: 503 });
      return new Response("ok", { status: 200 });
    }) as typeof fetch;

    try {
      const resp = await fetchWithRetry("https://example.test/x", undefined, {
        retries: 3,
        baseDelayMs: 1,
        label: "test",
      });
      expect(resp.status).toBe(200);
      expect(calls).toBe(2);
    } finally {
      globalThis.fetch = original;
    }
  });
});
