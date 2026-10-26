import type { AdvisoryEntry, Finding } from "../src/lib/types.ts";
import { buildFixPlan } from "../src/lib/fixer.ts";
import { consumerVariantsForFamily, detectMavenRenames, topLevelAncestors } from "../src/lib/maven-renames.ts";

const jacksonAdvisory: AdvisoryEntry = {
  id: "GHSA-5jmj-h7xm-6q6v",
  aliases: ["CVE-2026-54515"],
  ecosystems: ["Maven"],
  summary: "jackson-databind case-insensitive issue",
  severity: [],
  affected: [
    {
      package: { name: "com.fasterxml.jackson.core:jackson-databind", ecosystem: "Maven" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.1.0" }] }],
    },
    {
      package: { name: "tools.jackson.core:jackson-databind", ecosystem: "Maven" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.1.0" }, { fixed: "3.1.4" }] }],
    },
  ],
  links: [],
};

const jacksonFinding: Finding = {
  id: "GHSA-5jmj-h7xm-6q6v",
  aliases: ["CVE-2026-54515"],
  ecosystem: "maven",
  packageName: "com.fasterxml.jackson.core:jackson-databind",
  installedVersion: "3.1.4",
  vulnerableRange: "3.1.0+",
  fixedVersions: ["3.1.4"],
  severity: "UNKNOWN",
  summary: "jackson-databind vulnerability",
  references: [],
};

describe("detectMavenRenames", () => {
  it("suggests tools.jackson.core when OSV fixes new coordinates", () => {
    const renames = detectMavenRenames([jacksonFinding], [jacksonAdvisory]);
    expect(renames.length).toBe(1);
    expect(renames[0].toPackage).toBe("tools.jackson.core:jackson-databind");
    expect(renames[0].targetVersion).toBe("3.1.4");
  });

  it("suggests rename instead of cross-major bump on com.fasterxml 2.x", () => {
    const finding: Finding = {
      ...jacksonFinding,
      installedVersion: "2.21.4",
      fixedVersions: ["3.1.4"],
    };
    const renames = detectMavenRenames([finding], []);
    expect(renames.length).toBe(1);
    expect(renames[0].toPackage).toBe("tools.jackson.core:jackson-databind");
    expect(renames[0].targetVersion).toBe("3.1.4");
  });

  it("skips rename when same-major in-place fix exists", () => {
    const finding: Finding = {
      ...jacksonFinding,
      installedVersion: "2.21.4",
      fixedVersions: ["2.21.5", "3.1.4"],
    };
    const renames = detectMavenRenames([finding], []);
    expect(renames).toEqual([]);
  });

  it("skips rename when another finding on same package has same-major fix", () => {
    const renameOnly: Finding = {
      ...jacksonFinding,
      id: "GHSA-5jmj-h7xm-6q6v",
      installedVersion: "2.19.2",
      fixedVersions: ["3.1.4"],
    };
    const sameMajor: Finding = {
      ...jacksonFinding,
      id: "GHSA-hgj6-7826-r7m5",
      installedVersion: "2.19.2",
      fixedVersions: ["2.18.8", "2.21.4", "3.1.4"],
    };
    const renames = detectMavenRenames([renameOnly, sameMajor], []);
    expect(renames).toEqual([]);
  });
});

describe("buildFixPlan renames", () => {
  it("puts coordinate migrations in renames instead of unfixable", () => {
    const plan = buildFixPlan([jacksonFinding], [jacksonAdvisory]);
    expect(plan.fixable).toEqual([]);
    expect(plan.unfixable).toEqual([]);
    expect(plan.renames.length).toBe(1);
    expect(plan.renames[0].renameTo).toBe("tools.jackson.core:jackson-databind");
  });

  it("prefers rename over cross-major com.fasterxml bump when only 3.x fix exists", () => {
    const finding: Finding = {
      ...jacksonFinding,
      installedVersion: "2.21.4",
      fixedVersions: ["3.1.4"],
    };
    const plan = buildFixPlan([finding], []);
    expect(plan.fixable).toEqual([]);
    expect(plan.renames.length).toBe(1);
    expect(plan.renames[0].renameTo).toBe("tools.jackson.core:jackson-databind");
  });
});

describe("consumerVariantsForFamily", () => {
  it("returns the jetty wiremock variant and nothing for other families", () => {
    const jetty = consumerVariantsForFamily("jetty");
    expect(jetty.length).toBe(1);
    expect(jetty[0].from).toBe("org.wiremock:wiremock");
    expect(jetty[0].to).toBe("org.wiremock:wiremock-jetty12");
    expect(consumerVariantsForFamily("jackson")).toEqual([]);
  });
});

describe("topLevelAncestors", () => {
  it("reports a direct dependency as its own top-level source", () => {
    const pkgs = [
      { name: "com.ey.emailapi:email-api" }, // project artifact (tree root line)
      { name: "org.wiremock:wiremock", requiredBy: ["com.ey.emailapi:email-api"] },
      { name: "org.eclipse.jetty:jetty-server", requiredBy: ["org.wiremock:wiremock"] },
    ];
    expect([...topLevelAncestors("org.eclipse.jetty:jetty-server", pkgs)]).toEqual(["org.wiremock:wiremock"]);
    expect([...topLevelAncestors("org.wiremock:wiremock", pkgs)]).toEqual(["org.wiremock:wiremock"]);
  });

  it("walks transitive chains to their top-level roots", () => {
    const pkgs = [
      { name: "com.app:app" }, // project artifact (tree root line)
      { name: "g:a", requiredBy: ["com.app:app"] },
      { name: "g:b", requiredBy: ["g:a"] },
      { name: "g:c", requiredBy: ["g:b"] },
      { name: "g:d", requiredBy: ["g:c", "g:b"] },
    ];
    expect([...topLevelAncestors("g:d", pkgs)].sort()).toEqual(["g:a"]);
  });

  it("treats a coordinate whose only parent is the absent project artifact as top-level", () => {
    const pkgs = [
      { name: "g:a", requiredBy: ["com.ey.emailapi:email-api"] },
    ];
    expect([...topLevelAncestors("g:a", pkgs)]).toEqual(["g:a"]);
  });

  it("treats a parent that is itself a root-line entry (project artifact) as the boundary", () => {
    const pkgs = [
      { name: "g:a", requiredBy: ["com.ey.emailapi:email-api"] },
      { name: "com.ey.emailapi:email-api" }, // present, never required by anything
    ];
    expect([...topLevelAncestors("g:a", pkgs)]).toEqual(["g:a"]);
  });

  it("terminates on cycles without reporting anything", () => {
    const pkgs = [
      { name: "g:x", requiredBy: ["g:y"] },
      { name: "g:y", requiredBy: ["g:x"] },
    ];
    expect(topLevelAncestors("g:x", pkgs).size).toBe(0);
  });

  it("reports both a direct occurrence and transitive sources of the same coordinate", () => {
    const pkgs = [
      { name: "com.app:app" }, // project artifact (tree root line)
      { name: "g:a" }, // direct occurrence (no parents)
      { name: "g:a", requiredBy: ["g:b"] }, // also pulled transitively
      { name: "g:b", requiredBy: ["g:c"] },
      { name: "g:c", requiredBy: ["com.app:app"] }, // direct dependency of the project
    ];
    expect([...topLevelAncestors("g:a", pkgs)].sort()).toEqual(["g:a", "g:c"]);
  });
});
