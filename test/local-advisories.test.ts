import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadLocalAdvisories, getLocalAdvisoriesDir } from "../src/lib/local-advisories.ts";
import { matchVulnerabilities } from "../src/lib/matcher.ts";
import type { PackageRef } from "../src/lib/types.ts";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "local-adv-"));
}

describe("published package", () => {
  it("ships the local-advisories directory", () => {
    const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { files: string[] };
    expect(pkg.files).toContain("local-advisories/");
  });
});

describe("loadLocalAdvisories", () => {
  it("returns [] when the directory does not exist", () => {
    expect(loadLocalAdvisories(path.join(tempDir(), "nope"))).toEqual([]);
  });

  it("loads entries from every json file, array or single object", () => {
    const dir = tempDir();
    fs.writeFileSync(
      path.join(dir, "Maven.json"),
      JSON.stringify([{ id: "CVE-1", ecosystems: ["Maven"] }, { id: "CVE-2", ecosystems: ["Maven"] }]),
    );
    fs.writeFileSync(path.join(dir, "npm.json"), JSON.stringify({ id: "CVE-3", ecosystems: ["npm"] }));

    const loaded = loadLocalAdvisories(dir);
    expect(loaded.map((e) => e.id).sort()).toEqual(["CVE-1", "CVE-2", "CVE-3"]);
  });

  it("skips malformed files without throwing and keeps the valid ones", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "bad.json"), "{ not json");
    fs.writeFileSync(path.join(dir, "good.json"), JSON.stringify([{ id: "CVE-9", ecosystems: ["Maven"] }]));

    expect(loadLocalAdvisories(dir).map((e) => e.id)).toEqual(["CVE-9"]);
  });
});

describe("vendored BouncyCastle 1.86 advisories (data contract)", () => {
  const pkg = (name: string, version: string): PackageRef => ({
    ecosystem: "maven",
    name,
    version,
    manifestPath: "build.gradle",
  });

  it("flags bcprov/bcpkix below 1.86 and leaves 1.86 clean", () => {
    const advisories = loadLocalAdvisories(getLocalAdvisoriesDir());
    expect(advisories.length).toBeGreaterThanOrEqual(8);

    const vulnerable = matchVulnerabilities(
      [pkg("org.bouncycastle:bcprov-jdk18on", "1.85.2"), pkg("org.bouncycastle:bcpkix-jdk18on", "1.85")],
      advisories,
    );
    expect(vulnerable).toHaveLength(8);
    expect(vulnerable.every((f) => f.fixedVersions[0] === "1.86")).toBe(true);

    const clean = matchVulnerabilities(
      [pkg("org.bouncycastle:bcprov-jdk18on", "1.86"), pkg("org.bouncycastle:bcpkix-jdk18on", "1.86")],
      advisories,
    );
    expect(clean).toHaveLength(0);
  });
});

describe("vendored OSV-orphan Maven advisories (data contract)", () => {
  const pkg = (name: string, version: string): PackageRef => ({
    ecosystem: "maven",
    name,
    version,
    manifestPath: "build.gradle",
  });

  it("flags guava below 33.7.2-jre with the fix and leaves 33.7.2-jre clean", () => {
    const advisories = loadLocalAdvisories(getLocalAdvisoriesDir());

    const vulnerable = matchVulnerabilities([pkg("com.google.guava:guava", "32.1.3-jre")], advisories);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0].id).toBe("CVE-2026-102554");
    expect(vulnerable[0].fixedVersions[0]).toBe("33.7.2-jre");

    const clean = matchVulnerabilities([pkg("com.google.guava:guava", "33.7.2-jre")], advisories);
    expect(clean).toHaveLength(0);
  });

  it("flags jaxb-core at or above 4.0.0-M4 with no fix and leaves 3.x clean", () => {
    const advisories = loadLocalAdvisories(getLocalAdvisoriesDir());

    const vulnerable = matchVulnerabilities([pkg("org.glassfish.jaxb:jaxb-core", "4.0.9")], advisories);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0].id).toBe("CVE-2026-92877");
    expect(vulnerable[0].fixedVersions).toEqual([]);

    const clean = matchVulnerabilities([pkg("org.glassfish.jaxb:jaxb-core", "3.0.2")], advisories);
    expect(clean).toHaveLength(0);
  });
});
