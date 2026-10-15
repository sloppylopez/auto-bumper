import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { FixCandidate } from "../src/lib/fixer.ts";
import type { PackageRef } from "../src/lib/types.ts";
import {
  filterRedundantFixes,
  mixedMigrationClusters,
  planSignature,
} from "../src/lib/fix-plan-filter.ts";

describe("mixedMigrationClusters", () => {
  it("detects old and new jackson groups together", () => {
    const packages: PackageRef[] = [
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-core", version: "2.21.4", manifestPath: "b" },
      { ecosystem: "maven", name: "tools.jackson.core:jackson-databind", version: "3.1.4", manifestPath: "b" },
    ];
    const mixed = mixedMigrationClusters(packages);
    expect(mixed.size).toBe(1);
  });
});

describe("filterRedundantFixes", () => {
  it("keeps rename when migration cluster is mixed on classpath", () => {
    const renames: FixCandidate[] = [{
      packageName: "com.fasterxml.jackson.core:jackson-databind",
      installedVersion: "2.19.2",
      targetVersion: "3.1.4",
      isMajor: true,
      findingIds: ["GHSA-x"],
      severity: "HIGH",
      renameTo: "tools.jackson.core:jackson-databind",
      isRename: true,
    }];
    const packages: PackageRef[] = [
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-core", version: "2.19.2", manifestPath: "b" },
      { ecosystem: "maven", name: "tools.jackson.core:jackson-databind", version: "3.1.4", manifestPath: "b" },
    ];
    const { renames: out } = filterRedundantFixes([], renames, packages);
    expect(out.length).toBe(1);
  });

  it("allows rename when mixed but old coord still in build.gradle", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-filter-"));
    const gradlePath = path.join(dir, "build.gradle");
    fs.writeFileSync(gradlePath, 'implementation("com.fasterxml.jackson.core:jackson-core")\n', "utf-8");
    try {
      const renames: FixCandidate[] = [{
        packageName: "com.fasterxml.jackson.core:jackson-core",
        installedVersion: "2.21.4",
        targetVersion: "3.1.4",
        isMajor: true,
        findingIds: ["GHSA-x"],
        severity: "HIGH",
        renameTo: "tools.jackson.core:jackson-core",
        isRename: true,
      }];
      const packages: PackageRef[] = [
        { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-core", version: "2.19.2", manifestPath: gradlePath },
        { ecosystem: "maven", name: "tools.jackson.core:jackson-databind", version: "3.1.4", manifestPath: gradlePath },
      ];
      const { renames: out } = filterRedundantFixes([], renames, packages, [gradlePath]);
      expect(out.length).toBe(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps an npm prerelease bump that maven order would call already done", () => {
    const fixable: FixCandidate[] = [{
      packageName: "left-pad",
      installedVersion: "2.0.0-1",
      targetVersion: "2.0.0",
      isMajor: false,
      findingIds: ["GHSA-x"],
      severity: "HIGH",
      ecosystem: "npm",
    }];
    const { fixable: out, skipped } = filterRedundantFixes(fixable, [], []);
    expect(out).toHaveLength(1);
    expect(skipped).toEqual([]);
  });

  it("keeps a pypi post-release bump that maven order would call already done", () => {
    const fixable: FixCandidate[] = [{
      packageName: "requests",
      installedVersion: "1.0",
      targetVersion: "1.0.post1",
      isMajor: false,
      findingIds: ["GHSA-x"],
      severity: "HIGH",
      ecosystem: "pypi",
    }];
    const { fixable: out, skipped } = filterRedundantFixes(fixable, [], []);
    expect(out).toHaveLength(1);
    expect(skipped).toEqual([]);
  });
});

describe("planSignature", () => {
  it("is stable for same plan", () => {
    const a = planSignature(
      [{ packageName: "a:lib", targetVersion: "2.0" }],
      [{ packageName: "b:old", renameTo: "b:new", targetVersion: "3.0" }],
    );
    const b = planSignature(
      [{ packageName: "a:lib", targetVersion: "2.0" }],
      [{ packageName: "b:old", renameTo: "b:new", targetVersion: "3.0" }],
    );
    expect(a).toBe(b);
  });
});
