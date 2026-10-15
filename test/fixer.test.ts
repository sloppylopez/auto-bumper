import type { Finding } from "../src/lib/types.ts";
import { buildFixPlan, withNextFixVersion } from "../src/lib/fixer.ts";

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

describe("buildFixPlan", () => {
  it("empty findings returns {fixable: [], unfixable: [], renames: []}", () => {
    const plan = buildFixPlan([]);
    expect(plan.fixable).toEqual([]);
    expect(plan.unfixable).toEqual([]);
    expect(plan.renames).toEqual([]);
  });

  it("single finding with fixedVersions goes into fixable", () => {
    const findings = [makeFinding({ fixedVersions: ["4.6.0"] })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].packageName).toBe("lodash");
    expect(plan.fixable[0].targetVersion).not.toBeNull();
  });

  it("finding with no fixedVersions goes into unfixable", () => {
    const findings = [makeFinding({ fixedVersions: [] })];
    const plan = buildFixPlan(findings);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].packageName).toBe("lodash");
    expect(plan.unfixable[0].targetVersion).toBeNull();
  });

  it("multiple findings for same package are grouped together", () => {
    const findings = [
      makeFinding({ id: "GHSA-1", fixedVersions: ["4.6.0"] }),
      makeFinding({ id: "GHSA-2", fixedVersions: ["4.7.0"] }),
    ];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].findingIds.length).toBe(2);
    // Target should be the max of minimal fixes — at least one that covers both
    expect(plan.fixable[0].targetVersion).not.toBeNull();
  });

  it("major version bump detected when target crosses major boundary", () => {
    const findings = [makeFinding({
      installedVersion: "1.0.0",
      fixedVersions: ["2.0.0"],
      packageName: "react",
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].isMajor).toBe(true);
  });

  it("no major flag when staying within same major version", () => {
    const findings = [makeFinding({
      installedVersion: "4.5.0",
      fixedVersions: ["4.6.0"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable[0].isMajor).toBe(false);
  });

  it("prefers same-major fix over cross-major jump", () => {
    const findings = [makeFinding({
      ecosystem: "maven",
      packageName: "com.fasterxml.jackson.core:jackson-databind",
      installedVersion: "2.21.4",
      fixedVersions: ["2.21.5", "3.1.4"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable[0].targetVersion).toBe("2.21.5");
    expect(plan.fixable[0].isMajor).toBe(false);
  });

  it("maven cross-major same-coords fix goes into fixable with isMajor for the major gate", () => {
    const findings = [makeFinding({
      ecosystem: "maven",
      packageName: "com.google.guava:guava",
      installedVersion: "32.1.3-jre",
      fixedVersions: ["33.7.2-jre"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.unfixable).toEqual([]);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("33.7.2-jre");
    expect(plan.fixable[0].isMajor).toBe(true);
  });

  it("prefers same-major bump over rename when both fixes exist", () => {
    const findings = [makeFinding({
      ecosystem: "maven",
      packageName: "com.fasterxml.jackson.core:jackson-databind",
      installedVersion: "2.21.4",
      fixedVersions: ["2.21.5", "3.1.4"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("2.21.5");
    expect(plan.renames).toEqual([]);
  });

  it("mixed findings on same package take the max fix so one bump covers all advisories", () => {
    const findings = [
      makeFinding({
        id: "GHSA-5jmj-h7xm-6q6v",
        ecosystem: "maven",
        packageName: "com.fasterxml.jackson.core:jackson-databind",
        installedVersion: "2.19.2",
        fixedVersions: ["3.1.4"],
      }),
      makeFinding({
        id: "GHSA-hgj6-7826-r7m5",
        ecosystem: "maven",
        packageName: "com.fasterxml.jackson.core:jackson-databind",
        installedVersion: "2.19.2",
        fixedVersions: ["2.18.8", "2.21.4", "3.1.4"],
      }),
    ];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("3.1.4");
    expect(plan.fixable[0].isMajor).toBe(true);
    expect(plan.renames).toEqual([]);
  });

  it("fixable candidates sorted by severity descending", () => {
    const findings = [
      makeFinding({ id: "low-finding", severity: "LOW", packageName: "pkg-a", installedVersion: "1.0.0", fixedVersions: ["1.1.0"] }),
      makeFinding({ id: "crit-finding", severity: "CRITICAL", packageName: "pkg-b", installedVersion: "2.0.0", fixedVersions: ["2.1.0"] }),
    ];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(2);
    expect(plan.fixable[0].severity).toBe("CRITICAL");
    expect(plan.fixable[1].severity).toBe("LOW");
  });

  it("sets ecosystem on fixable candidates", () => {
    const plan = buildFixPlan([makeFinding({ ecosystem: "npm", fixedVersions: ["4.6.0"] })]);
    expect(plan.fixable[0].ecosystem).toBe("npm");
  });
});

describe("withNextFixVersion", () => {
  const candidate = {
    packageName: "org.example:lib",
    installedVersion: "1.5",
    targetVersion: null,
    isMajor: false,
    findingIds: ["CVE-INCLUSIVE"],
    severity: "HIGH" as const,
    ecosystem: "maven",
    lastAffected: "1.9",
  };

  it("uses the next published release and never the inclusive bound", () => {
    const promoted = withNextFixVersion(candidate, "1.10");
    expect(promoted?.targetVersion).toBe("1.10");
    expect(promoted?.targetVersion).not.toBe("1.9");
  });

  it("stays unfixable when nothing newer is published", () => {
    expect(withNextFixVersion(candidate, null)).toBeNull();
    expect(withNextFixVersion(candidate, "1.9")).toBeNull();
  });
});
