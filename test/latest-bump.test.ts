import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, mock } from "bun:test";
import { extractMetadataVersions, latestReleaseVersion } from "../src/lib/repo-metadata.ts";
import { parsePomXmlDirect } from "../src/lib/parse-lockfile.ts";
import { compareMavenVersion } from "../src/lib/matcher.ts";

// Stub the network lookup before cli/fix.ts is imported (it binds at import time).
// Dynamic imports below are the module-load-boundary exception to static-import rules:
// mock.module must run after the real repo-metadata loads and before cli/fix.ts binds it.
const actualRepoMetadata = await import("../src/lib/repo-metadata.ts");
const latestStubTable: Record<string, string> = {
  "ch.qos.logback:logback-core": "1.6.5",
  "org.postgresql:postgresql": "42.7.14",
};
mock.module("../src/lib/repo-metadata.ts", () => ({
  ...actualRepoMetadata,
  findLatestAvailableVersion: async (
    _manifestPath: string,
    _kind: "gradle" | "maven",
    packageName: string,
    currentVersion: string,
  ): Promise<{ version: string | null; metadataFound: boolean }> => {
    const target = latestStubTable[packageName];
    if (!target) return { version: null, metadataFound: false };
    return { version: compareMavenVersion(target, currentVersion) > 0 ? target : null, metadataFound: true };
  },
}));

const { buildLatestCandidates } = await import("../cli/fix.ts");

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-latest-"));
function tempFile(name: string, content: string): string {
  const file = path.join(tmpDir, name);
  fs.writeFileSync(file, content);
  return file;
}

describe("extractMetadataVersions", () => {
  it("reads <version> entries in document order and keeps <latest>", () => {
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <versioning>
    <latest>42.7.14</latest>
    <release>42.7.14</release>
    <versions>
      <version>42.7.3</version>
      <version>42.7.4</version>
      <version>42.7.5</version>
      <version>42.7.14</version>
    </versions>
  </versioning>
</metadata>`;
    expect(extractMetadataVersions(body)).toEqual(["42.7.3", "42.7.4", "42.7.5", "42.7.14"]);
  });

  it("returns [] when no versions are listed", () => {
    expect(extractMetadataVersions("<metadata><groupId>x</groupId></metadata>")).toEqual([]);
  });
});

describe("latestReleaseVersion", () => {
  it("picks the newest non-prerelease strictly newer than current", () => {
    expect(latestReleaseVersion(["42.7.5", "42.7.13", "42.7.14"], "42.7.13")).toBe("42.7.14");
  });

  it("excludes prereleases and snapshots", () => {
    expect(latestReleaseVersion(["1.0.0", "2.0.0-rc1", "2.0.0-alpha", "2.1.0-SNAPSHOT"], "1.0.0")).toBeNull();
  });

  it("keeps the qualifier suffix matching current on numeric ties", () => {
    // 33.7.2-android and 33.7.2-jre compare equal (unknown qualifiers); -jre wins for a -jre install.
    expect(latestReleaseVersion(["33.7.2-android", "33.7.2-jre"], "33.6.0-jre")).toBe("33.7.2-jre");
  });

  it("returns null when nothing is newer or input is empty", () => {
    expect(latestReleaseVersion(["1.0.0", "1.2.0"], "1.2.0")).toBeNull();
    expect(latestReleaseVersion([], "1.0.0")).toBeNull();
  });
});

describe("parsePomXmlDirect", () => {
  it("resolves ${property} versions from the pom's own <properties>", () => {
    // The ${...} below are literal POM property refs, escaped for the template literal.
    const pom = tempFile("pom.xml", `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <foo.version>1.2.3</foo.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.foo</groupId>
      <artifactId>bar</artifactId>
      <version>${"${"}foo.version}</version>
    </dependency>
    <dependency>
      <groupId>com.baz</groupId>
      <artifactId>qux</artifactId>
      <version>${"${"}missing.version}</version>
    </dependency>
  </dependencies>
</project>`);
    const { packages, warnings } = parsePomXmlDirect(pom);
    expect(packages).toContainEqual(expect.objectContaining({ name: "com.foo:bar", version: "1.2.3" }));
    expect(packages.some(p => p.name === "com.baz:qux")).toBe(false);
    expect(warnings.some(w => w.includes("property ref"))).toBe(true);
  });
});

const GRADLE_FIXTURE = `def logback_version = "1.6.3"
def postgresql_version = "42.7.13"

dependencies {
    implementation "ch.qos.logback:logback-core:\${logback_version}"
    testImplementation "ch.qos.logback:logback-core:\${logback_version}"
    implementation "org.postgresql:postgresql:\${postgresql_version}"
}

dependencyManagement {
    dependencies {
        dependency('ch.qos.logback:logback-core:1.6.4')
    }
}
`;

describe("buildLatestCandidates", () => {
  const gradleFile = tempFile("build.gradle", GRADLE_FIXTURE);
  const project = { kind: "gradle" as const, manifestPath: gradleFile, label: "fixture" };

  it("bumps every directly declared coordinate to its latest release", async () => {
    const candidates = await buildLatestCandidates(project, [], new Set());
    expect(candidates).toHaveLength(2);
    const logback = candidates.find(c => c.packageName === "ch.qos.logback:logback-core")!;
    // Two declarations share the ${logback_version} var (deduped to one ref at 1.6.3);
    // the managed-block pin 1.6.4 wins via max-dedupe.
    expect(logback).toMatchObject({
      installedVersion: "1.6.4",
      targetVersion: "1.6.5",
      isMajor: false,
      latest: true,
      findingIds: [],
      ecosystem: "maven",
    });
    const pg = candidates.find(c => c.packageName === "org.postgresql:postgresql")!;
    expect(pg).toMatchObject({ installedVersion: "42.7.13", targetVersion: "42.7.14", isMajor: false, latest: true });
  });

  it("honours --exclude coordinates", async () => {
    const candidates = await buildLatestCandidates(project, [], new Set(["org.postgresql:postgresql"]));
    expect(candidates.map(c => c.packageName)).toEqual(["ch.qos.logback:logback-core"]);
  });

  it("drops coordinates already at their latest release", async () => {
    const allPackages = [
      { name: "ch.qos.logback:logback-core", version: "1.6.5" },
      { name: "org.postgresql:postgresql", version: "42.7.13" },
    ];
    const candidates = await buildLatestCandidates(project, allPackages, new Set());
    expect(candidates.map(c => c.packageName)).toEqual(["org.postgresql:postgresql"]);
  });

  it("returns [] for non-maven projects", async () => {
    const npmProject = { kind: "npm" as const, manifestPath: gradleFile, label: "fixture" };
    expect(await buildLatestCandidates(npmProject, [], new Set())).toEqual([]);
  });
});
