import { afterEach, describe, expect, it } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AdvisoryEntry } from "../src/lib/types.ts";
import { GRADLE_MARKER_BEGIN, GRADLE_MARKER_END } from "../src/lib/brand.ts";
import { computeProtectedPinsByProject } from "../cli/fix.ts";

// Regression: the auto-bumper deleted the jaxb-core vulnerability-escape pin in a consumer project
// because the project's own force (jaxb-core@4.0.9) shadowed it — even though that forced
// version is itself affected by CVE-2026-92877 and our pin (last resolutionStrategy.force wins)
// was what kept the tree clean. Protection must survive shadowing when the user-forced version
// is affected, and yield only when the user's explicit force pins a clean version.

const jaxbAdvisory: AdvisoryEntry = {
  id: "SNYK-JAVA-ORGGLASSFISHJAXB-1234567",
  aliases: ["CVE-2026-92877"],
  ecosystems: ["Maven"],
  affected: [{
    package: { name: "org.glassfish.jaxb:jaxb-core", ecosystem: "Maven" },
    ranges: [{
      type: "ECOSYSTEM",
      events: [{ introduced: "4.0.0-M4" }], // no fix published — only an escape below introduced works
    }],
  }],
};

function gradleFile(userForceVersion: string): { dir: string; manifestPath: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "escape-pin-"));
  const content = [
    `def jaxb_version = "${userForceVersion}"`,
    ``,
    `configurations.all {`,
    `    resolutionStrategy {`,
    `        force "org.glassfish.jaxb:jaxb-core:\${jaxb_version}"`,
    `    }`,
    `}`,
    ``,
    GRADLE_MARKER_BEGIN,
    `dependencies {`,
    `    constraints {`,
    `        implementation('org.glassfish.jaxb:jaxb-core:3.0.2') { because 'CVE-2026-92877' }`,
    `    }`,
    `}`,
    `configurations.all {`,
    `    resolutionStrategy {`,
    `        force 'org.glassfish.jaxb:jaxb-core:3.0.2'`,
    `    }`,
    `}`,
    GRADLE_MARKER_END,
  ].join("\n");
  const manifestPath = path.join(dir, "build.gradle");
  fs.writeFileSync(manifestPath, content);
  return { dir, manifestPath };
}

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) {
    const d = tempDirs.pop()!;
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

describe("computeProtectedPinsByProject shadow filter", () => {
  it("keeps protection when the project's own force pins an affected version (escape pin must survive)", () => {
    const { dir, manifestPath } = gradleFile("4.0.9");
    tempDirs.push(dir);
    const bomMaps = new Map([[manifestPath, new Map([["org.glassfish.jaxb:jaxb-core", "4.0.9"]])]]);
    const out = computeProtectedPinsByProject(
      [{ kind: "gradle", manifestPath, label: "root" }],
      bomMaps,
      [jaxbAdvisory],
    );
    expect(out.get(manifestPath)?.has("org.glassfish.jaxb:jaxb-core")).toBe(true);
  });

  it("drops protection when the project's own force pins a clean version (user decision wins)", () => {
    // Unlike the no-fix advisory above, this one has a fixed boundary: forcing 5.0.0 (== fixed)
    // is a genuinely clean user decision, so our escape pin below `introduced` yields to it.
    const fixedAdvisory: AdvisoryEntry = {
      ...jaxbAdvisory,
      affected: [{
        package: { name: "org.glassfish.jaxb:jaxb-core", ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.0.0-M4" }, { fixed: "5.0.0" }] }],
      }],
    };
    const { dir, manifestPath } = gradleFile("5.0.0");
    tempDirs.push(dir);
    const bomMaps = new Map([[manifestPath, new Map([["org.glassfish.jaxb:jaxb-core", "4.0.9"]])]]);
    const out = computeProtectedPinsByProject(
      [{ kind: "gradle", manifestPath, label: "root" }],
      bomMaps,
      [fixedAdvisory],
    );
    expect(out.get(manifestPath)?.size ?? 0).toBe(0);
  });
});
