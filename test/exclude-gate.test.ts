import { describe, it, expect } from "bun:test";
import { filterByExcludeGate } from "../cli/fix.ts";
import type { FixCandidate } from "../src/lib/fixer.ts";
import type { PackageRef } from "../src/lib/types.ts";

const gradleProject = { kind: "gradle" as const, manifestPath: "/tmp/gate/build.gradle", label: "gate" };

function unfixable(packageName: string): FixCandidate {
  return { packageName, installedVersion: "4.0.9", targetVersion: null, isMajor: false, findingIds: ["CVE-2026-92877"], severity: "HIGH" };
}

// jaxb-core is required by two other resolved packages (diamond); leaf-lib by nothing.
const packages: PackageRef[] = [
  { ecosystem: "maven", name: "org.glassfish.jaxb:jaxb-core", version: "4.0.9", manifestPath: "build.gradle", requiredBy: ["com.sun.xml.ws:jaxws-rt", "org.glassfish.jaxb:jaxb-runtime"] },
  { ecosystem: "maven", name: "com.sun.xml.ws:jaxws-rt", version: "4.0.3", manifestPath: "build.gradle", requiredBy: ["com.example:app"] },
  { ecosystem: "maven", name: "org.glassfish.jaxb:jaxb-runtime", version: "4.0.9", manifestPath: "build.gradle", requiredBy: ["com.example:app"] },
  { ecosystem: "maven", name: "com.example:leaf-lib", version: "1.2.3", manifestPath: "build.gradle" },
];

describe("filterByExcludeGate (dependent-aware)", () => {
  it("refuses to exclude a coordinate that other resolved packages depend on", async () => {
    const { approved, warnings } = await filterByExcludeGate(
      [unfixable("org.glassfish.jaxb:jaxb-core")],
      [gradleProject],
      new Set(), // preApproved
      new Set(), // failed
      packages,
      new Set(), // forceExclude
    );
    expect(approved).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("Refused to exclude org.glassfish.jaxb:jaxb-core");
    expect(warnings[0]).toContain("com.sun.xml.ws:jaxws-rt");
    expect(warnings[0]).toContain("org.glassfish.jaxb:jaxb-runtime");
    expect(warnings[0]).toContain("--force-exclude=org.glassfish.jaxb:jaxb-core");
  });

  it("still approves a leaf coordinate via pre-approval without prompting", async () => {
    const { approved, warnings } = await filterByExcludeGate(
      [unfixable("com.example:leaf-lib")],
      [gradleProject],
      new Set(["com.example:leaf-lib"]), // preApproved
      new Set(), // failed
      packages,
      new Set(), // forceExclude
    );
    expect(approved.map(c => c.packageName)).toEqual(["com.example:leaf-lib"]);
    expect(warnings).toEqual([]);
  });

  it("approves a depended-on coordinate when --force-exclude covers it", async () => {
    const { approved, warnings } = await filterByExcludeGate(
      [unfixable("org.glassfish.jaxb:jaxb-core")],
      [gradleProject],
      new Set(["org.glassfish.jaxb:jaxb-core"]), // preApproved
      new Set(), // failed
      packages,
      new Set(["org.glassfish.jaxb:jaxb-core"]), // forceExclude
    );
    expect(approved.map(c => c.packageName)).toEqual(["org.glassfish.jaxb:jaxb-core"]);
    expect(warnings).toEqual([]);
  });

  it("normalizes candidate coordinate case against tree edges and --force-exclude", async () => {
    const coord = "org.GlassFish.JAXB:JAXB-CORE"; // different case than the resolved-tree entry
    // Without force, refusal still fires — proves the mixed-case candidate matched its lowercase tree dependents.
    const refused = await filterByExcludeGate([unfixable(coord)], [gradleProject], new Set(), new Set(), packages, new Set());
    expect(refused.approved).toEqual([]);
    expect(refused.warnings[0]).toContain("Refused to exclude org.GlassFish.JAXB:JAXB-CORE");
    // With force (lowercase set, as the CLI parses it), approval proceeds via pre-approval.
    const forced = await filterByExcludeGate([unfixable(coord)], [gradleProject], new Set([coord]), new Set(), packages, new Set(["org.glassfish.jaxb:jaxb-core"]));
    expect(forced.approved.map(c => c.packageName)).toEqual([coord]);
    expect(forced.warnings).toEqual([]);
  });
});
