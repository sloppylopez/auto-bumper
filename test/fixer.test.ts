import type { Finding, AdvisoryEntry } from "../src/lib/types.ts";
import { buildFixPlan, packageAdvisoryEntries, pickSafeEscapeVersion, planFamilyMigrations, withDowngradeVersion, withNextFixVersion } from "../src/lib/fixer.ts";

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

  it("never targets a pre-release fixed version — no GA fix means unfixable", () => {
    const findings = [makeFinding({
      ecosystem: "maven",
      packageName: "org.hibernate.validator:hibernate-validator",
      installedVersion: "9.1.5.Final",
      fixedVersions: ["9.2.0.Beta1"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable).toEqual([]);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].targetVersion).toBeNull();
    expect(plan.unfixable[0].preReleaseOnlyFix).toBe("9.2.0.Beta1");
  });

  it("prefers a GA fix when pre-release and GA fixed versions both exist", () => {
    const findings = [makeFinding({
      ecosystem: "maven",
      packageName: "org.example:example-lib",
      installedVersion: "8.0.0.Final",
      fixedVersions: ["9.2.0.Beta1", "9.3.0.Final"],
    })];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("9.3.0.Final");
    expect(plan.fixable[0].preReleaseOnlyFix).toBeUndefined();
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

describe("withDowngradeVersion", () => {
  const candidate = {
    packageName: "org.glassfish.jaxb:jaxb-core",
    installedVersion: "4.0.5",
    targetVersion: null,
    isMajor: false,
    findingIds: ["GHSA-JAXB"],
    severity: "HIGH" as const,
    ecosystem: "maven",
    introduced: "3.0.3",
  };

  it("uses a release strictly below the introduced bound and flags it as a downgrade", () => {
    const promoted = withDowngradeVersion(candidate, "3.0.2");
    expect(promoted?.targetVersion).toBe("3.0.2");
    expect(promoted?.isDowngrade).toBe(true);
  });

  it("never targets the introduced bound itself (still vulnerable)", () => {
    expect(withDowngradeVersion(candidate, "3.0.3")).toBeNull();
  });

  it("refuses a release at or above the installed version", () => {
    expect(withDowngradeVersion(candidate, "4.0.5")).toBeNull();
    expect(withDowngradeVersion(candidate, "4.1.0")).toBeNull();
  });

  it("returns null without an introduced bound or with no previous release", () => {
    expect(withDowngradeVersion({ ...candidate, introduced: undefined }, "3.0.2")).toBeNull();
    expect(withDowngradeVersion(candidate, null)).toBeNull();
  });

  it("marks isMajor when the downgrade crosses a major boundary", () => {
    const promoted = withDowngradeVersion(candidate, "2.3.9");
    expect(promoted?.isMajor).toBe(true);
  });

  it("ignores candidates that already have a forward fix", () => {
    expect(withDowngradeVersion({ ...candidate, targetVersion: "4.0.6" }, "3.0.2")).toBeNull();
  });
});

describe("buildFixPlan introduced propagation", () => {
  const mavenFinding = (id: string, introduced?: string): Finding => makeFinding({
    id,
    ecosystem: "maven",
    packageName: "org.example:lib",
    installedVersion: "4.0.5",
    fixedVersions: [],
    vulnerableRange: ">=3.0.3",
    introduced,
  });

  it("takes the minimum introduced across findings of one package", () => {
    const plan = buildFixPlan([mavenFinding("GHSA-1", "3.0.3"), mavenFinding("GHSA-2", "3.1.0")]);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].introduced).toBe("3.0.3");
  });

  it("leaves introduced undefined when any finding lacks the bound", () => {
    const plan = buildFixPlan([mavenFinding("GHSA-1", "3.0.3"), mavenFinding("GHSA-2")]);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].introduced).toBeUndefined();
  });

  it("returns an empty downgrades list", () => {
    expect(buildFixPlan([]).downgrades).toEqual([]);
  });
});

describe("pickSafeEscapeVersion", () => {
  const jsonPatchVersions = ["1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13"];
  const affectedPoints = new Set(["1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.11", "1.12", "1.13"]);

  it("down-walk from an affected point lands on the safe hole below (json-patch 1.13 → 1.10)", () => {
    expect(pickSafeEscapeVersion(jsonPatchVersions, "1.13", "down", "maven", v => affectedPoints.has(v))).toBe("1.10");
  });

  it("up-walk returns null when every release above is affected (json-patch 1.12 → no escape)", () => {
    expect(pickSafeEscapeVersion(jsonPatchVersions, "1.12", "up", "maven", v => affectedPoints.has(v))).toBeNull();
  });

  it("returns null in both directions when windows cover the whole range", () => {
    const versions = ["1.12", "1.13"];
    expect(pickSafeEscapeVersion(versions, "1.12", "up", "maven", () => true)).toBeNull();
    expect(pickSafeEscapeVersion(versions, "1.13", "down", "maven", () => true)).toBeNull();
  });

  it("skips pre-releases when walking up", () => {
    const versions = ["1.2", "1.14-SNAPSHOT", "1.15"];
    expect(pickSafeEscapeVersion(versions, "1.2", "up", "maven", v => v === "1.2")).toBe("1.15");
  });

  it("returns null when nothing is published in the direction", () => {
    expect(pickSafeEscapeVersion(["2.0"], "1.5", "down", "maven", () => false)).toBeNull();
  });
});

describe("packageAdvisoryEntries", () => {
  const mavenEntry: AdvisoryEntry = {
    id: "GHSA-1", aliases: [], ecosystems: ["maven"], summary: "", severity: [],
    affected: [{ package: { name: "com.fasterxml.jackson.core:jackson-databind" } }], links: [],
  };
  const pypiEntry: AdvisoryEntry = {
    id: "GHSA-2", aliases: [], ecosystems: ["pypi"], summary: "", severity: [],
    affected: [{ package: { name: "requests" } }], links: [],
  };

  it("keeps only entries whose affected block names the package in that ecosystem", () => {
    expect(packageAdvisoryEntries([mavenEntry, pypiEntry], "com.fasterxml.jackson.core:jackson-databind", "maven")).toEqual([mavenEntry]);
  });

  it("matches package names case-insensitively", () => {
    expect(packageAdvisoryEntries([mavenEntry], "COM.FASTERXML.JACKSON.CORE:JACKSON-DATABIND", "maven")).toEqual([mavenEntry]);
  });
});

describe("family consistency", () => {
  const mavenRef = (packageName: string, installedVersion: string) => ({ packageName, installedVersion, ecosystem: "maven" as const });

  it("clamps a cross-major jetty bump to the best same-line fix when siblings stay on the old line", () => {
    const findings = [
      makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["11.0.29"] }),
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] }),
    ];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
      mavenRef("org.eclipse.jetty.http2:http2-common", "11.0.24"),
    ];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("11.0.29");
    expect(plan.fixable[0].isMajor).toBe(false);
    expect(plan.unfixable).toEqual([]);
  });

  it("demotes to unfixable when no same-line fix exists", () => {
    const findings = [
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] }),
    ];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
      mavenRef("org.eclipse.jetty.http2:http2-common", "11.0.24"),
    ];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable).toEqual([]);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].targetVersion).toBeNull();
    expect(plan.unfixable[0].familyClamped).toContain("split family 'jetty'");
  });

  it("allows the whole family to move cross-major together", () => {
    const findings = [
      makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] }),
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-server", installedVersion: "11.0.24", fixedVersions: ["12.0.13"] }),
    ];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
    ];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable.length).toBe(2);
    expect(plan.fixable.map(c => c.targetVersion)).toEqual(["12.0.12", "12.0.13"]);
    expect(plan.fixable.every(c => c.isMajor)).toBe(true);
  });

  it("leaves a cross-major candidate alone when no family siblings are on the classpath", () => {
    const findings = [
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] }),
    ];
    const plan = buildFixPlan(findings, [], [mavenRef("org.eclipse.jetty:jetty-http", "11.0.24")]);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("12.0.12");
    expect(plan.fixable[0].isMajor).toBe(true);
    expect(plan.fixable[0].familyClamped).toBeUndefined();
  });

  it("does not touch packages outside the family table", () => {
    const findings = [
      makeFinding({ id: "GHSA-x", ecosystem: "maven", packageName: "com.example:thing", installedVersion: "1.0.0", fixedVersions: ["2.0.0"] }),
    ];
    const classpath = [mavenRef("com.example:thing", "1.0.0"), mavenRef("com.example:other", "1.0.0")];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("2.0.0");
    expect(plan.fixable[0].isMajor).toBe(true);
  });

  it("demotes a cross-major jaxb bump when siblings stay on the old line", () => {
    const findings = [
      makeFinding({ id: "GHSA-j", ecosystem: "maven", packageName: "org.glassfish.jaxb:jaxb-core", installedVersion: "3.0.9", fixedVersions: ["4.0.5"] }),
    ];
    const classpath = [
      mavenRef("org.glassfish.jaxb:jaxb-core", "3.0.9"),
      mavenRef("org.glassfish.jaxb:jaxb-runtime", "3.0.9"),
    ];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable).toEqual([]);
    expect(plan.unfixable.length).toBe(1);
    expect(plan.unfixable[0].familyClamped).toContain("split family 'jaxb'");
  });

  it("lets the whole jaxb family move cross-major together", () => {
    const findings = [
      makeFinding({ id: "GHSA-j", ecosystem: "maven", packageName: "org.glassfish.jaxb:jaxb-core", installedVersion: "3.0.9", fixedVersions: ["4.0.5"] }),
      makeFinding({ id: "GHSA-k", ecosystem: "maven", packageName: "org.glassfish.jaxb:jaxb-runtime", installedVersion: "3.0.9", fixedVersions: ["4.0.5"] }),
    ];
    const classpath = [
      mavenRef("org.glassfish.jaxb:jaxb-core", "3.0.9"),
      mavenRef("org.glassfish.jaxb:jaxb-runtime", "3.0.9"),
    ];
    const plan = buildFixPlan(findings, [], classpath);
    expect(plan.fixable.length).toBe(2);
    expect(plan.fixable.every(c => c.isMajor)).toBe(true);
  });

  it("without a classpath argument keeps the legacy cross-major behavior", () => {
    const findings = [
      makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["11.0.29"] }),
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] }),
    ];
    const plan = buildFixPlan(findings);
    expect(plan.fixable.length).toBe(1);
    expect(plan.fixable[0].targetVersion).toBe("12.0.12");
    expect(plan.fixable[0].isMajor).toBe(true);
    expect(plan.fixable[0].familyClamped).toBeUndefined();
  });
});

describe("planFamilyMigrations", () => {
  const mavenRef = (packageName: string, installedVersion: string) => ({ packageName, installedVersion, ecosystem: "maven" as const });

  it("plans a migration for a co-versioned family with an affected member and siblings", () => {
    const findings = [
      makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["11.0.29", "12.0.12"] }),
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-server", installedVersion: "11.0.24", fixedVersions: ["12.0.13"] }),
    ];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
      mavenRef("org.eclipse.jetty.http2:http2-common", "11.0.24"),
    ];
    const migrations = planFamilyMigrations(classpath, findings);
    expect(migrations.length).toBe(1);
    expect(migrations[0].familyName).toBe("jetty");
    expect([...migrations[0].memberPackages].sort()).toEqual([
      "org.eclipse.jetty.http2:http2-common",
      "org.eclipse.jetty:jetty-http",
      "org.eclipse.jetty:jetty-server",
    ]);
    // Newest installed line (in-place pin) first, then the next line and any line carrying a fix.
    expect(migrations[0].linesToTry).toEqual([11, 12]);
  });

  it("returns [] when no family member is affected", () => {
    const findings = [makeFinding({ id: "GHSA-x", ecosystem: "maven", packageName: "com.example:thing", installedVersion: "1.0.0", fixedVersions: ["2.0.0"] })];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
    ];
    expect(planFamilyMigrations(classpath, findings)).toEqual([]);
  });

  it("skips a family with a single classpath member (no coherence to enforce)", () => {
    const findings = [makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["12.0.12"] })];
    const classpath = [mavenRef("org.eclipse.jetty:jetty-http", "11.0.24")];
    expect(planFamilyMigrations(classpath, findings)).toEqual([]);
  });

  it("falls back to the next line above the installed one when no fix version exists", () => {
    const findings = [
      makeFinding({ id: "GHSA-a", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-http", installedVersion: "11.0.24", fixedVersions: ["11.0.29"] }),
      makeFinding({ id: "GHSA-b", ecosystem: "maven", packageName: "org.eclipse.jetty:jetty-server", installedVersion: "11.0.24", fixedVersions: [] }),
    ];
    const classpath = [
      mavenRef("org.eclipse.jetty:jetty-http", "11.0.24"),
      mavenRef("org.eclipse.jetty:jetty-server", "11.0.24"),
    ];
    const migrations = planFamilyMigrations(classpath, findings);
    expect(migrations.length).toBe(1);
    expect(migrations[0].linesToTry).toEqual([11, 12]);
  });
});
