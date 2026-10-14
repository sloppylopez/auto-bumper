import { GRADLE_MARKER_BEGIN, GRADLE_MARKER_END } from "../src/lib/brand.ts";
import {
  analyzeBuildGradleContent,
  analyzeFixPlan,
  analyzeMavenPackages,
} from "../src/lib/gradle-health.ts";
import { expandRenameBundle } from "../src/lib/maven-renames.ts";
import type { FixCandidate } from "../src/lib/fixer.ts";
import type { PackageRef } from "../src/lib/types.ts";

describe("analyzeMavenPackages", () => {
  it("warns when old and new migration groups both appear", () => {
    const packages: PackageRef[] = [
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-core", version: "2.21.4", manifestPath: "build.gradle" },
      { ecosystem: "maven", name: "tools.jackson.core:jackson-databind", version: "3.1.4", manifestPath: "build.gradle" },
    ];
    const warnings = analyzeMavenPackages(packages);
    expect(warnings.some(w => w.includes("Mixed Maven coordinates"))).toBe(true);
  });
});

describe("analyzeBuildGradleContent", () => {
  it("warns when build file mixes migration groups", () => {
    const content = `
dependencies {
  implementation "com.fasterxml.jackson.core:jackson-core:2.21.4"
  implementation "tools.jackson.core:jackson-databind:3.1.4"
}`;
    const warnings = analyzeBuildGradleContent(content);
    expect(warnings.some(w => w.includes("Mixed Maven coordinates"))).toBe(true);
  });

  it("warns on managed exclude of a migration source group", () => {
    const content = `
${GRADLE_MARKER_BEGIN}
configurations.all {
  exclude group: 'com.fasterxml.jackson.core', module: 'jackson-databind'
}
${GRADLE_MARKER_END}`;
    const warnings = analyzeBuildGradleContent(content);
    expect(warnings.some(w => w.includes("excludes com.fasterxml.jackson.core"))).toBe(true);
  });
});

describe("expandRenameBundle", () => {
  it("bundles siblings in the same migration cluster", () => {
    const anchor: FixCandidate = {
      packageName: "com.fasterxml.jackson.core:jackson-databind",
      installedVersion: "2.21.4",
      targetVersion: "3.1.4",
      isMajor: true,
      findingIds: ["GHSA-x"],
      severity: "HIGH",
      renameTo: "tools.jackson.core:jackson-databind",
      isRename: true,
    };
    const packages: PackageRef[] = [
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-databind", version: "2.21.4", manifestPath: "build.gradle" },
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-core", version: "2.21.4", manifestPath: "build.gradle" },
      { ecosystem: "maven", name: "com.fasterxml.jackson.core:jackson-annotations", version: "2.21.4", manifestPath: "build.gradle" },
    ];
    const expanded = expandRenameBundle([anchor], packages);
    expect(expanded).toHaveLength(2);
    expect(expanded.map(r => r.packageName)).toContain("com.fasterxml.jackson.core:jackson-core");
    expect(expanded.map(r => r.packageName)).not.toContain("com.fasterxml.jackson.core:jackson-annotations");
  });
});

describe("analyzeFixPlan", () => {
  it("warns on platform constraint bump", () => {
    const plan = {
      fixable: [{
        packageName: "org.springframework.boot:spring-boot",
        installedVersion: "3.5.0",
        targetVersion: "3.5.14",
        isMajor: false,
        findingIds: ["GHSA-y"],
        severity: "HIGH" as const,
      }],
      unfixable: [],
      renames: [],
    };
    const warnings = analyzeFixPlan(plan, []);
    expect(warnings.some(w => w.includes("platform plugin/BOM"))).toBe(true);
  });
});
