import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "bun:test";
import { applyBumps as applyNpmBumps } from "../src/lib/npm-editor.ts";
import { applyBumps as applyCargoBumps, applyRenames as applyCargoRenames } from "../src/lib/cargo-editor.ts";
import { applyToPyprojectToml, applyToRequirementsTxt } from "../src/lib/python-editor.ts";
import { applyBumps as applyGradleBumps } from "../src/lib/gradle-editor.ts";
import {
  compareMavenVersion,
  comparePackageVersion,
  matchesMavenRange,
  matchesPEP440Range,
  matchesSemverRange,
  matchVulnerabilities,
} from "../src/lib/matcher.ts";
import { dedupeResolvedPackages, parseLockfile, parseRequirementsTxt, windowsBatchArgs } from "../src/lib/parse-lockfile.ts";
import { assertNoZipSlip, zipEntryNames } from "../src/lib/osv-export.ts";
import { extractNextLink } from "../src/lib/github-repo-advisories.ts";
import { isInsideDir } from "../src/path.ts";
import { filterPackagesByEcosystem } from "../src/lib/ecosystem-filter.ts";
import { mapOsvVulnToAdvisory } from "../src/lib/osv-export.ts";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-fix-"));
}

describe("npm version rewrite", () => {
  it("keeps an exact pin exact and keeps the full >= operator", () => {
    const dir = tempDir();
    const file = path.join(dir, "package.json");
    fs.writeFileSync(file, JSON.stringify({
      dependencies: { lodash: "4.17.21", leftpad: ">=1.0.0" },
      optionalDependencies: { debug: "~4.3.0" },
    }, null, 2));
    try {
      const result = applyNpmBumps(file, [
        { packageName: "lodash", targetVersion: "4.17.22", because: [] },
        { packageName: "leftpad", targetVersion: "1.1.0", because: [] },
        { packageName: "debug", targetVersion: "4.3.4", because: [] },
        { packageName: "minimist", targetVersion: "1.2.8", because: [] },
      ]);
      const pkg = JSON.parse(fs.readFileSync(file, "utf-8"));
      expect(pkg.dependencies.lodash).toBe("4.17.22");
      expect(pkg.dependencies.leftpad).toBe(">=1.1.0");
      expect(pkg.optionalDependencies.debug).toBe("~4.3.4");
      expect(pkg.overrides.minimist).toBe("1.2.8");
      expect(result.missed).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("turns an upper bound into a floor and writes yarn or pnpm pins", () => {
    const dir = tempDir();
    const file = path.join(dir, "package.json");
    fs.writeFileSync(path.join(dir, "yarn.lock"), "");
    fs.writeFileSync(file, JSON.stringify({ dependencies: { leftpad: "<=1.0.0" } }));
    try {
      applyNpmBumps(file, [
        { packageName: "leftpad", targetVersion: "1.1.0", because: [] },
        { packageName: "minimist", targetVersion: "1.2.8", because: [] },
      ]);
      const pkg = JSON.parse(fs.readFileSync(file, "utf-8"));
      expect(pkg.dependencies.leftpad).toBe(">=1.1.0");
      expect(pkg.resolutions.minimist).toBe("1.2.8");
      expect(pkg.overrides).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }

    const pnpmDir = tempDir();
    const pnpmFile = path.join(pnpmDir, "package.json");
    fs.writeFileSync(path.join(pnpmDir, "pnpm-lock.yaml"), "");
    fs.writeFileSync(pnpmFile, JSON.stringify({ dependencies: {} }));
    try {
      applyNpmBumps(pnpmFile, [{ packageName: "minimist", targetVersion: "1.2.8", because: [] }]);
      const pkg = JSON.parse(fs.readFileSync(pnpmFile, "utf-8"));
      expect(pkg.pnpm.overrides.minimist).toBe("1.2.8");
      expect(pkg.overrides).toBeUndefined();
    } finally {
      fs.rmSync(pnpmDir, { recursive: true, force: true });
    }
  });

  it("does not replace a workspace spec with a bare version", () => {
    const dir = tempDir();
    const file = path.join(dir, "package.json");
    fs.writeFileSync(file, JSON.stringify({ dependencies: { app: "workspace:*" } }));
    try {
      const result = applyNpmBumps(file, [{ packageName: "app", targetVersion: "1.2.3", because: [] }]);
      const pkg = JSON.parse(fs.readFileSync(file, "utf-8"));
      expect(pkg.dependencies.app).toBe("workspace:*");
      expect(result.missed).toContain("app");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("python manifest rewrite", () => {
  it("bumps requirements.txt names that do not start with w", () => {
    const dir = tempDir();
    const file = path.join(dir, "requirements.txt");
    fs.writeFileSync(file, "requests==2.31.0\n  flask>=2.0.0\n");
    try {
      const result = applyToRequirementsTxt(file, [
        { packageName: "requests", targetVersion: "2.32.0", because: [] },
        { packageName: "Flask", targetVersion: "3.0.0", because: [] },
      ]);
      const text = fs.readFileSync(file, "utf-8");
      expect(text).toContain("requests==2.32.0");
      expect(text).toContain("flask>=3.0.0");
      expect(result.missed).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not turn an exclusion pin into an exclusion of the fix", () => {
    const dir = tempDir();
    const file = path.join(dir, "requirements.txt");
    fs.writeFileSync(file, "requests!=2.31.0\n");
    try {
      const result = applyToRequirementsTxt(file, [
        { packageName: "requests", targetVersion: "2.32.0", because: [] },
      ]);
      expect(fs.readFileSync(file, "utf-8")).toContain("requests!=2.31.0");
      expect(result.missed).toContain("requests");
      expect(result.warnings.some(w => w.includes("!="))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("bumps an indented poetry dependency", () => {
    const dir = tempDir();
    const file = path.join(dir, "pyproject.toml");
    fs.writeFileSync(file, "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \">=2.31.0\"\n");
    try {
      applyToPyprojectToml(file, [{ packageName: "requests", targetVersion: "2.32.0", because: [] }]);
      const text = fs.readFileSync(file, "utf-8");
      expect(text).toContain("requests = \">=2.32.0\"");
      expect(text).toContain("python = \"^3.11\"");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("turns <= and < into a floor that includes the fix", () => {
    const dir = tempDir();
    const req = path.join(dir, "requirements.txt");
    const py = path.join(dir, "pyproject.toml");
    fs.writeFileSync(req, "requests<=2.31.0\nflask<2.32.0\n");
    fs.writeFileSync(py, "[project]\ndependencies = [\n  \"numpy<=1.26.0\",\n  \"click<8.1.0\",\n]\n\n[tool.poetry.dependencies]\nhttpx = \"<0.27.0\"\n");
    try {
      applyToRequirementsTxt(req, [
        { packageName: "requests", targetVersion: "2.32.0", because: [] },
        { packageName: "flask", targetVersion: "2.32.0", because: [] },
      ]);
      applyToPyprojectToml(py, [
        { packageName: "numpy", targetVersion: "1.26.4", because: [] },
        { packageName: "click", targetVersion: "8.1.7", because: [] },
        { packageName: "httpx", targetVersion: "0.27.0", because: [] },
      ]);
      const reqText = fs.readFileSync(req, "utf-8");
      const pyText = fs.readFileSync(py, "utf-8");
      expect(reqText).toContain("requests>=2.32.0");
      expect(reqText).toContain("flask>=2.32.0");
      expect(reqText).not.toContain("<");
      expect(pyText).toContain("numpy>=1.26.4");
      expect(pyText).toContain("click>=8.1.7");
      expect(pyText).toContain("httpx = \">=0.27.0\"");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("cargo rewrite", () => {
  it("keeps an exact crate pin exact", () => {
    const dir = tempDir();
    const file = path.join(dir, "Cargo.toml");
    fs.writeFileSync(file, "[dependencies]\nserde = \"1.0.0\"\ntokio = { version = \"1.0.0\", features = [\"fs\"] }\n");
    try {
      applyCargoBumps(file, [
        { packageName: "serde", targetVersion: "1.0.210", because: [] },
        { packageName: "tokio", targetVersion: "1.40.0", because: [] },
      ]);
      const text = fs.readFileSync(file, "utf-8");
      expect(text).toContain("serde = \"1.0.210\"");
      expect(text).toContain("version = \"1.40.0\"");
      expect(text).toContain("features = [\"fs\"]");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("turns an upper bound into a floor that includes the fix", () => {
    const dir = tempDir();
    const file = path.join(dir, "Cargo.toml");
    fs.writeFileSync(file, "[dependencies]\ntokio = \"<1.40.0\"\nserde = \"<=1.0.200\"\n");
    try {
      applyCargoBumps(file, [
        { packageName: "tokio", targetVersion: "1.40.0", because: [] },
        { packageName: "serde", targetVersion: "1.0.210", because: [] },
      ]);
      const text = fs.readFileSync(file, "utf-8");
      expect(text).toContain("tokio = \">=1.40.0\"");
      expect(text).toContain("serde = \">=1.0.210\"");
      expect(text).not.toContain("<");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rename writes the target version", () => {
    const dir = tempDir();
    const file = path.join(dir, "Cargo.toml");
    fs.writeFileSync(file, "[dependencies]\nold_crate = \"1.0.0\"\n");
    try {
      applyCargoRenames(file, [{
        fromPackage: "old_crate",
        toPackage: "new_crate",
        targetVersion: "2.0.0",
        because: [],
      }]);
      const text = fs.readFileSync(file, "utf-8");
      expect(text).toContain("new_crate = \"2.0.0\"");
      expect(text).not.toContain("old_crate");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("requirements.txt installed versions", () => {
  it("records exact pins and floors, and skips ceilings and exclusions", () => {
    const dir = tempDir();
    const file = path.join(dir, "requirements.txt");
    fs.writeFileSync(file, "requests==2.31.0\nclick===8.1.7\nflask>=2.0.0\nnumpy<=1.26.0\nhttpx<0.27.0\nwerkzeug!=2.2.0\n");
    try {
      const parsed = parseRequirementsTxt(file);
      const byName = new Map(parsed.packages.map(p => [p.name, p.version]));
      expect(byName.get("requests")).toBe("2.31.0");
      expect(byName.get("click")).toBe("8.1.7");
      expect(byName.get("flask")).toBe("2.0.0");
      expect(byName.has("numpy")).toBe(false);
      expect(byName.has("httpx")).toBe(false);
      expect(byName.has("werkzeug")).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("version matching", () => {
  it("maven range does not match outside the interval", () => {
    expect(matchesMavenRange("1.5", "[1.0,2.0)")).toBe(true);
    expect(matchesMavenRange("2.0", "[1.0,2.0)")).toBe(false);
    expect(matchesMavenRange("0.9", "[1.0,2.0)")).toBe(false);
  });

  it("maven alpha and rc sort before the release", () => {
    expect(compareMavenVersion("1.0-alpha", "1.0")).toBeLessThan(0);
    expect(compareMavenVersion("1.0-rc1", "1.0")).toBeLessThan(0);
    expect(compareMavenVersion("1.0-SNAPSHOT", "1.0")).toBeLessThan(0);
    expect(compareMavenVersion("4.2.0.Final", "4.2.0")).toBe(0);
  });

  it("semver does not collapse minor 100 into the next major", () => {
    expect(matchesSemverRange("1.100.0", ">=2.0.0")).toBe(false);
    expect(matchesSemverRange("1.100.0", "<2.0.0")).toBe(true);
    expect(comparePackageVersion("1.2.3-beta", "1.2.3", "npm")).toBeLessThan(0);
    expect(comparePackageVersion("1.0.0-alpha.10", "1.0.0-alpha.2", "npm")).toBeGreaterThan(0);
  });

  it("reads a CVSS vector as a base score", () => {
    const adv = mapOsvVulnToAdvisory({
      id: "GHSA-test",
      summary: "remote code execution in lodash",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      affected: [{
        package: { ecosystem: "npm", name: "lodash" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      }],
    });
    const findings = matchVulnerabilities(
      [{ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "package-lock.json" }],
      [adv],
    );
    expect(findings[0]?.severity).toBe("CRITICAL");
  });

  it("unknown pep440 clause does not match every version", () => {
    expect(matchesPEP440Range("1.2.3", "??1.0")).toBe(false);
    expect(matchesPEP440Range("9.0.0", ">=1.0,<2.0")).toBe(false);
  });
});

describe("dependency discovery", () => {
  it("keeps both versions of the same coordinate", () => {
    const pkgs = dedupeResolvedPackages([
      { ecosystem: "maven", name: "org.foo:bar", version: "1.0.0", manifestPath: "build.gradle" },
      { ecosystem: "maven", name: "org.foo:bar", version: "2.0.0", manifestPath: "build.gradle" },
    ]);
    expect(pkgs.map(p => p.version).sort()).toEqual(["1.0.0", "2.0.0"]);
  });

  it("reads package.json when no lockfile exists", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
      dependencies: { lodash: "^4.17.21" },
    }));
    try {
      const parsed = parseLockfile(dir);
      expect(parsed.packages.some(p => p.name === "lodash" && p.version === "4.17.21")).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("treats build.gradle.kts as gradle", () => {
    const out = filterPackagesByEcosystem([{
      ecosystem: "maven",
      name: "com.example:lib",
      version: "1.0.0",
      manifestPath: "/proj/build.gradle.kts",
    }], "gradle");
    expect(out).toHaveLength(1);
  });
});

describe("gradle catalog and kotlin pin", () => {
  it("bumps a version.ref in libs.versions.toml", () => {
    const dir = tempDir();
    fs.mkdirSync(path.join(dir, "gradle"));
    fs.writeFileSync(path.join(dir, "build.gradle.kts"), "dependencies {\n}\n");
    fs.writeFileSync(path.join(dir, "gradle", "libs.versions.toml"), [
      "[versions]",
      "jackson = \"2.15.0\"",
      "[libraries]",
      "jackson = { module = \"com.fasterxml.jackson.core:jackson-core\", version.ref = \"jackson\" }",
      "",
    ].join("\n"));
    try {
      applyGradleBumps(path.join(dir, "build.gradle.kts"), [{
        packageName: "com.fasterxml.jackson.core:jackson-core",
        targetVersion: "2.17.0",
        because: ["GHSA-test"],
      }]);
      const toml = fs.readFileSync(path.join(dir, "gradle", "libs.versions.toml"), "utf-8");
      expect(toml).toContain("jackson = \"2.17.0\"");
      const build = fs.readFileSync(path.join(dir, "build.gradle.kts"), "utf-8");
      expect(build).not.toContain("implementation('");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("security guards", () => {
  it("quotes a batch path so cmd cannot split on &", () => {
    const line = windowsBatchArgs(String.raw`C:\ok & calc\gradlew.bat`, ["dependencies", "--quiet"]);
    expect(line.slice(0, 3)).toEqual(["/d", "/s", "/c"]);
    expect(line[3]).toBe(String.raw`""C:\ok & calc\gradlew.bat" "dependencies" "--quiet""`);
  });

  it("rejects a zip entry that climbs out of the extract dir", () => {
    expect(() => assertNoZipSlip(["ok.json", "../evil.json"])).toThrow(/escapes/);
  });

  it("reads names from a tiny zip central directory", () => {
    const name = "GHSA-1.json";
    const nameBuf = Buffer.from(name);
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(local, 30);
    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(0, 42);
    nameBuf.copy(central, 46);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(1, 8);
    eocd.writeUInt16LE(1, 10);
    eocd.writeUInt32LE(central.length, 12);
    eocd.writeUInt32LE(local.length, 16);
    const zip = Buffer.concat([local, central, eocd]);
    expect(zipEntryNames(zip)).toEqual([name]);
  });

  it("does not follow a next link off api.github.com", () => {
    expect(extractNextLink('<https://api.github.com/repos/netty/netty/security-advisories?page=2>; rel="next"'))
      .toContain("api.github.com");
    expect(extractNextLink('<https://evil.example/steal>; rel="next"')).toBeNull();
  });

  it("rejects paths that leave the project root", () => {
    const root = path.join(os.tmpdir(), "auto-bumper-root");
    expect(isInsideDir(root, path.join(root, "src"))).toBe(true);
    expect(isInsideDir(root, path.join(root, "..", "other"))).toBe(false);
  });
});
