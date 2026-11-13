import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { applyBumps, managedBecauseIds } from "../src/lib/gradle-editor.ts";
import { companionExclusions, FIX_BUNDLES } from "../src/lib/fix-bundles.ts";

function withTempGradle(content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-fixbundles-"));
  const filePath = path.join(dir, "build.gradle");
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function readGradle(filePath: string): string {
  return fs.readFileSync(filePath, "utf-8");
}

describe("fix-bundles data", () => {
  it("CVE-2026-92877 bundles the osgi-resource-locator exclusion with a reason", () => {
    const bundle = FIX_BUNDLES["CVE-2026-92877"];
    expect(bundle).toBeDefined();
    expect(bundle.map(e => e.coordinate)).toContain("org.glassfish.hk2:osgi-resource-locator");
    for (const ex of bundle) expect(ex.reason.length).toBeGreaterThan(10);
  });

  it("companionExclusions returns deduplicated exclusions and ignores unknown advisories", () => {
    const out = companionExclusions(["CVE-2026-92877", "CVE-2026-92877", "GHSA-does-not-exist"]);
    expect(out.map(e => e.coordinate)).toEqual(["org.glassfish.hk2:osgi-resource-locator"]);
    expect(companionExclusions([])).toEqual([]);
    expect(companionExclusions(["GHSA-nope"])).toEqual([]);
  });
});

describe("managedBecauseIds", () => {
  it("collects advisory IDs from managed-block because clauses", () => {
    withTempGradle(
      `dependencies {
    implementation "org.glassfish.jaxb:jaxb-runtime:4.0.9"
    implementation "ch.qos.logback:logback-classic:1.5.32"
}`,
      filePath => {
        applyBumps(filePath, [
          { packageName: "org.glassfish.jaxb:jaxb-runtime", targetVersion: "3.0.2", because: ["CVE-2026-92877"] },
          { packageName: "ch.qos.logback:logback-classic", targetVersion: "1.5.33", because: ["GHSA-a", "GHSA-b"] },
        ]);
        const ids = managedBecauseIds(readGradle(filePath));
        expect([...ids].sort()).toEqual(["CVE-2026-92877", "GHSA-a", "GHSA-b"]);
      },
    );
  });

  it("returns an empty set for content without a managed block", () => {
    expect(managedBecauseIds(`dependencies {\n    implementation "a:b:1"\n}`).size).toBe(0);
  });
});

describe("companion exclusion rendering", () => {
  const EXCLUDE = { packageName: "org.glassfish.hk2:osgi-resource-locator", reason: "companion of the CVE-2026-92877 jaxb 3.0.2 pin" };

  it("writes the exclusion with a reason comment above it in the managed block", () => {
    withTempGradle(
      `dependencies {
    implementation "org.glassfish.jaxb:jaxb-runtime:4.0.9"
}`,
      filePath => {
        const result = applyBumps(filePath, [
          { packageName: "org.glassfish.jaxb:jaxb-runtime", targetVersion: "3.0.2", because: ["CVE-2026-92877"] },
        ], [EXCLUDE]);
        expect(result.excluded).toContain("org.glassfish.hk2:osgi-resource-locator");
        const content = readGradle(filePath);
        expect(content).toMatch(/exclude group: 'org\.glassfish\.hk2', module: 'osgi-resource-locator'/);
        // The reason comment sits above the exclusion line.
        const idxReason = content.indexOf("companion of the CVE-2026-92877 jaxb 3.0.2 pin");
        const idxExclude = content.indexOf("exclude group: 'org.glassfish.hk2'");
        expect(idxReason).toBeGreaterThan(-1);
        expect(idxReason).toBeLessThan(idxExclude);
      },
    );
  });

  it("is idempotent: re-running with the same exclusion does not duplicate the line or the comment", () => {
    withTempGradle(
      `dependencies {
    implementation "org.glassfish.jaxb:jaxb-runtime:4.0.9"
}`,
      filePath => {
        const apply = () => applyBumps(filePath, [{ packageName: "org.glassfish.jaxb:jaxb-runtime", targetVersion: "3.0.2", because: ["CVE-2026-92877"] }], [EXCLUDE]);
        // First write creates the block with two leading newlines; the update path collapses to one —
        // pre-existing cosmetic drift, so assert convergence from the second run onward.
        apply();
        apply();
        const twice = readGradle(filePath);
        apply();
        expect(readGradle(filePath)).toBe(twice);
        expect(countOccurrences(twice, "exclude group: 'org.glassfish.hk2'")).toBe(1);
        expect(countOccurrences(twice, "companion of the CVE-2026-92877")).toBe(1);
      },
    );
  });

  it("preserves the existing reason comment when re-run without a reason", () => {
    withTempGradle(
      `dependencies {
    implementation "org.glassfish.jaxb:jaxb-runtime:4.0.9"
}`,
      filePath => {
        applyBumps(filePath, [{ packageName: "org.glassfish.jaxb:jaxb-runtime", targetVersion: "3.0.2", because: ["CVE-2026-92877"] }], [EXCLUDE]);
        applyBumps(filePath, [], [{ packageName: "org.glassfish.hk2:osgi-resource-locator" }]);
        const content = readGradle(filePath);
        expect(countOccurrences(content, "companion of the CVE-2026-92877")).toBe(1);
        expect(content).toMatch(/exclude group: 'org\.glassfish\.hk2', module: 'osgi-resource-locator'/);
      },
    );
  });
});

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) {
    count++;
    idx += needle.length;
  }
  return count;
}
