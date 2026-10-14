import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "bun:test";
import {
  backupFile,
  backupPath,
  discardBackup,
  restoreFile,
  runApplyTransaction,
} from "../src/lib/backup.ts";
import { buildFixPlan, findingPackageKey } from "../src/lib/fixer.ts";
import { comparePackageVersion } from "../src/lib/matcher.ts";
import type { Finding } from "../src/lib/types.ts";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-p1-"));

afterAll(() => {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const makeFinding = (overrides: Partial<Finding>): Finding => ({
  id: "GHSA-test",
  aliases: [],
  ecosystem: "npm",
  packageName: "lodash",
  installedVersion: "4.5.0",
  vulnerableRange: "<4.6.0",
  fixedVersions: ["4.6.0"],
  severity: "LOW",
  summary: "Test vulnerability",
  references: [],
  ...overrides,
});

describe("findingPackageKey / buildFixPlan eco split", () => {
  it("keys include ecosystem", () => {
    expect(findingPackageKey({ ecosystem: "npm", packageName: "foo" })).toBe("npm:foo");
  });

  it("does not merge same package name across ecosystems", () => {
    const plan = buildFixPlan([
      makeFinding({
        id: "GHSA-npm",
        ecosystem: "npm",
        packageName: "requests",
        installedVersion: "1.0.0",
        fixedVersions: ["1.0.1"],
      }),
      makeFinding({
        id: "GHSA-pypi",
        ecosystem: "pypi",
        packageName: "requests",
        installedVersion: "2.0.0",
        fixedVersions: ["2.0.1"],
      }),
    ]);
    expect(plan.fixable).toHaveLength(2);
    expect(plan.fixable.map(c => c.ecosystem).sort()).toEqual(["npm", "pypi"]);
    expect(plan.fixable.find(c => c.ecosystem === "npm")?.targetVersion).toBe("1.0.1");
    expect(plan.fixable.find(c => c.ecosystem === "pypi")?.targetVersion).toBe("2.0.1");
  });
});

describe("comparePackageVersion", () => {
  it("routes pypi to PEP440 (pre-release before release)", () => {
    expect(comparePackageVersion("1.0a1", "1.0", "pypi")).toBeLessThan(0);
  });

  it("routes maven normally", () => {
    expect(comparePackageVersion("1.0-SNAPSHOT", "1.0", "maven")).toBeLessThan(0);
  });
});

describe("backupFile preserve-first", () => {
  it("keeps original bak across second backup", () => {
    const file = path.join(tmpRoot, "manifest.txt");
    fs.writeFileSync(file, "v1");
    backupFile(file);
    fs.writeFileSync(file, "v2");
    backupFile(file); // must not overwrite bak
    expect(fs.readFileSync(backupPath(file), "utf-8")).toBe("v1");
    restoreFile(file);
    expect(fs.readFileSync(file, "utf-8")).toBe("v1");
    discardBackup(file);
  });
});

describe("runApplyTransaction", () => {
  it("restores all files when apply throws mid-pass", () => {
    const a = path.join(tmpRoot, "a.txt");
    const b = path.join(tmpRoot, "b.txt");
    fs.writeFileSync(a, "A0");
    fs.writeFileSync(b, "B0");

    expect(() =>
      runApplyTransaction({
        prepare: () => {
          backupFile(a);
          backupFile(b);
        },
        restore: () => {
          restoreFile(a);
          restoreFile(b);
        },
        apply: () => {
          fs.writeFileSync(a, "A1");
          throw new Error("boom");
        },
      }),
    ).toThrow("boom");

    expect(fs.readFileSync(a, "utf-8")).toBe("A0");
    expect(fs.readFileSync(b, "utf-8")).toBe("B0");
    discardBackup(a);
    discardBackup(b);
  });

  it("keeps changes when apply succeeds", () => {
    const a = path.join(tmpRoot, "ok.txt");
    fs.writeFileSync(a, "before");
    runApplyTransaction({
      prepare: () => backupFile(a),
      restore: () => restoreFile(a),
      apply: () => fs.writeFileSync(a, "after"),
    });
    expect(fs.readFileSync(a, "utf-8")).toBe("after");
    discardBackup(a);
  });
});
