import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { extractMavenUnresolved, parseGradleTree } from "../src/lib/parse-lockfile.ts";
import { removeManagedPin as removeGradleManagedPin, restoreDeclaredVersion } from "../src/lib/gradle-editor.ts";
import { removeManagedPin as removeMavenManagedPin } from "../src/lib/pom-editor.ts";
import { selectUnresolvableRollbacks, type RollbackRecord } from "../src/lib/unresolvable.ts";
import type { PackageRef } from "../src/lib/types.ts";
import { extractRepoUrls, hostAcceptsEnvCredentials, pickNextVersion, repoRequestInit, versionInMetadata } from "../src/lib/repo-metadata.ts";

function pkg(name: string): PackageRef {
  return { ecosystem: "maven", name, version: "1.0.0", manifestPath: "/tmp/build.gradle" };
}

describe("parseGradleTree FAILED detection", () => {
  it("records a plain 'VERSION FAILED' node as unresolved and skips the package", () => {
    const out = [
      "+--- org.apache.tomcat.embed:tomcat-embed-core: 10.1.58 FAILED",
      "+--- com.example:lib: 1.2.3",
    ].join("\n");
    const result = parseGradleTree(out, "build.gradle");
    expect(result.unresolved).toEqual(["org.apache.tomcat.embed:tomcat-embed-core@10.1.58"]);
    expect(result.packages.map(p => p.name)).toEqual(["com.example:lib"]);
  });

  it("records the requested target of a 'V1 -> V2 FAILED' node", () => {
    const out = [
      "|    +--- org.apache.tomcat.embed:tomcat-embed-websocket: 10.1.57 -> 10.1.58 FAILED",
    ].join("\n");
    const result = parseGradleTree(out, "build.gradle");
    expect(result.unresolved).toEqual(["org.apache.tomcat.embed:tomcat-embed-websocket@10.1.58"]);
    expect(result.packages).toEqual([]);
  });

  it("dedupes repeated FAILED nodes for the same coordinate", () => {
    const out = [
      "+--- org.foo:bar: 2.0 FAILED",
      "\\--- org.foo:bar: 2.0 FAILED",
    ].join("\n");
    const result = parseGradleTree(out, "build.gradle");
    expect(result.unresolved).toEqual(["org.foo:bar@2.0"]);
  });

  it("leaves normal and arrow (non-FAILED) lines unaffected", () => {
    const out = [
      "+--- com.example:plain: 1.0.0",
      "+--- com.example:bumped: 1.0.0 -> 2.0.0",
      "\\--- com.example:constrained: 3.0.0 (n)",
    ].join("\n");
    const result = parseGradleTree(out, "build.gradle");
    expect(result.unresolved).toBeUndefined();
    const byName = new Map(result.packages.map(p => [p.name, p.version]));
    expect(byName.get("com.example:plain")).toBe("1.0.0");
    expect(byName.get("com.example:bumped")).toBe("2.0.0");
  });
});

describe("selectUnresolvableRollbacks", () => {
  const tomcat = "org.apache.tomcat.embed:tomcat-embed-core";
  const unresolved = [`${tomcat}@10.1.58`];

  it("matches a direct bump whose target is unresolvable", () => {
    const rec: RollbackRecord = { packageName: tomcat, from: "10.1.57", to: "10.1.58", method: "direct" };
    expect(selectUnresolvableRollbacks([rec], unresolved, [])).toEqual([rec]);
  });

  it("matches a constrained bump", () => {
    const rec: RollbackRecord = { packageName: tomcat, from: "10.1.57", to: "10.1.58", method: "constrained" };
    expect(selectUnresolvableRollbacks([rec], unresolved, [])).toEqual([rec]);
  });

  it("skips renames (cannot be rolled back automatically)", () => {
    const rec: RollbackRecord = {
      packageName: tomcat, from: `${tomcat}@10.1.57`, to: "org.tomcat.embed:core@10.1.58",
      method: "direct", isRename: true,
    };
    expect(selectUnresolvableRollbacks([rec], unresolved, [])).toEqual([]);
  });

  it("skips methods that are not direct/constrained bumps", () => {
    const rec: RollbackRecord = { packageName: tomcat, from: "10.1.57", to: "10.1.58", method: "npm" };
    expect(selectUnresolvableRollbacks([rec], unresolved, [])).toEqual([]);
  });

  it("returns nothing when there is no unresolved list", () => {
    const rec: RollbackRecord = { packageName: tomcat, from: "10.1.57", to: "10.1.58", method: "direct" };
    expect(selectUnresolvableRollbacks([rec], undefined, [])).toEqual([]);
    expect(selectUnresolvableRollbacks([rec], [], [])).toEqual([]);
  });

  it("skips coordinates that resolved in another configuration", () => {
    const rec: RollbackRecord = { packageName: tomcat, from: "10.1.57", to: "10.1.58", method: "direct" };
    expect(selectUnresolvableRollbacks([rec], unresolved, [pkg(tomcat)])).toEqual([]);
  });

  it("matches case-insensitively and dedupes repeated matches", () => {
    const rec: RollbackRecord = { packageName: tomcat.toUpperCase(), from: "10.1.57", to: "10.1.58", method: "direct" };
    expect(selectUnresolvableRollbacks([rec, rec], unresolved, [])).toEqual([rec]);
  });
});

describe("removeManagedPin (gradle)", () => {
  const BEGIN = "// auto-bumper:begin managed constraints (auto-generated, do not edit)";
  const END = "// auto-bumper:end";
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-unres-"));
    file = path.join(dir, "build.gradle");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("removes one pin (constraint + force) and keeps the rest of the block", () => {
    const content = [
      "plugins { id 'java' }",
      "",
      BEGIN,
      "dependencies {",
      "    constraints {",
      "        implementation('org.apache.tomcat.embed:tomcat-embed-core:10.1.58')",
      "        implementation('org.jsoup:jsoup:1.18.3')",
      "    }",
      "}",
      "configurations.all {",
      "    resolutionStrategy {",
      "        force 'org.apache.tomcat.embed:tomcat-embed-core:10.1.58'",
      "    }",
      "}",
      END,
      "",
      "task hello { doLast { println 'hi' } }",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(removeGradleManagedPin(file, "org.apache.tomcat.embed:tomcat-embed-core")).toBe(true);
    const next = fs.readFileSync(file, "utf-8");
    expect(next).not.toContain("tomcat-embed-core");
    expect(next).toContain("implementation('org.jsoup:jsoup:1.18.3')");
    expect(next).toContain(BEGIN);
    expect(next).toContain(END);
  });

  it("removes the whole block when the last pin goes, without merging adjacent lines", () => {
    const content = [
      "plugins { id 'java' }",
      "",
      BEGIN,
      "dependencies {",
      "    constraints {",
      "        implementation('org.jsoup:jsoup:1.18.3')",
      "    }",
      "}",
      END,
      "",
      "task hello { doLast { println 'hi' } }",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(removeGradleManagedPin(file, "org.jsoup:jsoup")).toBe(true);
    const next = fs.readFileSync(file, "utf-8");
    expect(next).not.toContain(BEGIN);
    expect(next).not.toContain(END);
    expect(next).toContain("plugins { id 'java' }\n");
    expect(next).toContain("task hello { doLast { println 'hi' } }");
    expect(next).not.toContain("plugins { id 'java' }task");
  });

  it("returns false and leaves the file untouched for unknown packages", () => {
    const content = [
      BEGIN,
      "dependencies {",
      "    constraints {",
      "        implementation('org.jsoup:jsoup:1.18.3')",
      "    }",
      "}",
      END,
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(removeGradleManagedPin(file, "com.example:missing")).toBe(false);
    expect(fs.readFileSync(file, "utf-8")).toBe(content);
  });
});

describe("removeManagedPin (maven)", () => {
  const BEGIN = "<!-- auto-bumper:begin managed pins (auto-generated, do not edit) -->";
  const END = "<!-- auto-bumper:end -->";
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-unres-"));
    file = path.join(dir, "pom.xml");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  function pomWithBlock(): string {
    return [
      "<project>",
      "  <modelVersion>4.0.0</modelVersion>",
      "  <dependencies>",
      "    <dependency><groupId>org.apache.tomcat.embed</groupId><artifactId>tomcat-embed-core</artifactId><version>10.1.57</version></dependency>",
      BEGIN,
      "    <dependency>",
      "      <groupId>org.apache.tomcat.embed</groupId>",
      "      <artifactId>tomcat-embed-core</artifactId>",
      "      <version>10.1.58</version>",
      "    </dependency>",
      "    <dependency>",
      "      <groupId>org.jsoup</groupId>",
      "      <artifactId>jsoup</artifactId>",
      "      <version>1.18.3</version>",
      "    </dependency>",
      END,
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n");
  }

  it("removes one pin and keeps the rest of the block, leaving direct deps untouched", () => {
    fs.writeFileSync(file, pomWithBlock());

    expect(removeMavenManagedPin(file, "org.apache.tomcat.embed:tomcat-embed-core")).toBe(true);
    const next = fs.readFileSync(file, "utf-8");
    // The pin (10.1.58) is gone; the user's direct dependency (10.1.57) remains.
    expect(next).not.toContain("10.1.58");
    expect(next).toContain("<version>10.1.57</version>");
    expect(next).toContain("<artifactId>jsoup</artifactId>");
    expect(next).toContain(BEGIN);
    expect(next).toContain(END);
  });

  it("removes the whole block when the last pin goes", () => {
    const content = pomWithBlock().replace(
      /<dependency>\s*<groupId>org\.jsoup<\/groupId>\s*<artifactId>jsoup<\/artifactId>\s*<version>1\.18\.3<\/version>\s*<\/dependency>/,
      "",
    );
    fs.writeFileSync(file, content);

    expect(removeMavenManagedPin(file, "org.apache.tomcat.embed:tomcat-embed-core")).toBe(true);
    const next = fs.readFileSync(file, "utf-8");
    expect(next).not.toContain(BEGIN);
    expect(next).not.toContain("10.1.58");
    expect(next).toContain("</project>");
  });

  it("returns false and leaves the file untouched for unknown packages", () => {
    const content = pomWithBlock();
    fs.writeFileSync(file, content);

    expect(removeMavenManagedPin(file, "com.example:missing")).toBe(false);
    expect(fs.readFileSync(file, "utf-8")).toBe(content);
  });
});

describe("restoreDeclaredVersion (gradle)", () => {
  const pkgName = "org.apache.tomcat.embed:tomcat-embed-core";
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-unres-"));
    file = path.join(dir, "build.gradle");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("downgrades a def version variable from the bumped value back to the declared one", () => {
    const content = [
      'def tomcat_version = "10.1.58"',
      "dependencies {",
      `    implementation("org.apache.tomcat.embed:tomcat-embed-core:\${tomcat_version}")`,
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(true);
    const next = fs.readFileSync(file, "utf-8");
    expect(next).toContain('def tomcat_version = "10.1.57"');
  });

  it("leaves the file unchanged when already at the declared version", () => {
    const content = [
      'def tomcat_version = "10.1.57"',
      "dependencies {",
      `    implementation("org.apache.tomcat.embed:tomcat-embed-core:\${tomcat_version}")`,
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(true);
    expect(fs.readFileSync(file, "utf-8")).toBe(content);
  });

  it("returns false and leaves the file untouched when the declaration is at an unexpected version", () => {
    const content = [
      'def tomcat_version = "9.9.9"',
      "dependencies {",
      `    implementation("org.apache.tomcat.embed:tomcat-embed-core:\${tomcat_version}")`,
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(false);
    expect(fs.readFileSync(file, "utf-8")).toBe(content);
  });

  it("restores a string-literal declaration", () => {
    const content = [
      "dependencies {",
      `    implementation("org.apache.tomcat.embed:tomcat-embed-core:10.1.58")`,
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(true);
    expect(fs.readFileSync(file, "utf-8")).toContain("org.apache.tomcat.embed:tomcat-embed-core:10.1.57");
  });

  it("restores a map-style declaration", () => {
    const content = [
      "dependencies {",
      `    implementation(group: 'org.apache.tomcat.embed', name: 'tomcat-embed-core', version: '10.1.58')`,
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(true);
    expect(fs.readFileSync(file, "utf-8")).toContain("version: '10.1.57'");
  });

  it("returns true without changes when no direct declaration exists (pin-only apply)", () => {
    const content = "dependencies {\n    implementation 'org.jsoup:jsoup:1.18.3'\n}\n";
    fs.writeFileSync(file, content);

    expect(restoreDeclaredVersion(file, pkgName, "10.1.57", "10.1.58")).toBe(true);
    expect(fs.readFileSync(file, "utf-8")).toBe(content);
  });
});

describe("pickNextVersion", () => {
  it("picks the smallest version strictly above the minimum", () => {
    expect(pickNextVersion(["10.1.57", "10.1.61", "10.1.60", "11.0.0"], "10.1.58")).toBe("10.1.60");
  });

  it("excludes SNAPSHOT versions from candidates", () => {
    expect(pickNextVersion(["2.0.0-SNAPSHOT"], "1.9")).toBeNull();
    expect(pickNextVersion(["2.0.0-SNAPSHOT", "2.0.1"], "1.9")).toBe("2.0.1");
  });

  it("returns null when nothing is above the minimum or the list is empty", () => {
    expect(pickNextVersion(["1.0.0", "2.0.0"], "2.0.0")).toBeNull();
    expect(pickNextVersion([], "1.0.0")).toBeNull();
  });
});

describe("hostAcceptsEnvCredentials", () => {
  it("sends credentials only to a real Artifactory or JFrog host", () => {
    expect(hostAcceptsEnvCredentials("artifactory.corp.example")).toBe(true);
    expect(hostAcceptsEnvCredentials("repo.artifactory.corp.example")).toBe(true);
    expect(hostAcceptsEnvCredentials("repo.example.jfrog.io")).toBe(true);
    expect(hostAcceptsEnvCredentials("notartifactory.example")).toBe(false);
    expect(hostAcceptsEnvCredentials("evil-artifactory.example")).toBe(false);
  });

  it("does not attach a password to http or to a plain Maven Central host", () => {
    const creds = { user: "me", pass: "secret" };
    const httpRepo = repoRequestInit("http://artifactory.corp.example/maven", creds);
    expect(httpRepo?.headers.Authorization).toBeUndefined();
    expect(httpRepo?.redirect).toBe("follow");

    const httpsRepo = repoRequestInit("https://artifactory.corp.example/maven", creds);
    expect(httpsRepo?.headers.Authorization).toBe(`Basic ${Buffer.from("me:secret").toString("base64")}`);
    expect(httpsRepo?.redirect).toBe("manual");

    const central = repoRequestInit("https://repo.maven.apache.org/maven2", creds);
    expect(central?.headers.Authorization).toBeUndefined();
    expect(central?.redirect).toBe("follow");
  });
});

describe("extractRepoUrls", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-unres-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("extracts explicit maven urls and shorthand repositories from gradle", () => {
    const file = path.join(dir, "build.gradle");
    fs.writeFileSync(file, [
      "repositories {",
      "    mavenCentral()",
      "    google()",
      "    maven { url 'https://repo.example.jfrog.io/artifactory/api/ivy/maven-all' }",
      "}",
      "",
    ].join("\n"));

    const urls = extractRepoUrls(file, "gradle");
    expect(urls).toHaveLength(3);
    expect(urls).toContain("https://repo.maven.apache.org/maven2");
    expect(urls).toContain("https://dl.google.com/dl/android/maven2");
    expect(urls).toContain("https://repo.example.jfrog.io/artifactory/api/ivy/maven-all");
  });

  it("extracts <url> entries from a pom and falls back to central when absent", () => {
    const withRepos = path.join(dir, "with.xml");
    fs.writeFileSync(withRepos, [
      "<project>",
      "  <repositories>",
      "    <repository><id>jfrog</id><url>https://repo.example.jfrog.io/artifactory/api/ivy/maven-all</url></repository>",
      "  </repositories>",
      "</project>",
      "",
    ].join("\n"));
    expect(extractRepoUrls(withRepos, "maven")).toEqual(["https://repo.example.jfrog.io/artifactory/api/ivy/maven-all"]);

    const bare = path.join(dir, "bare.xml");
    fs.writeFileSync(bare, "<project><modelVersion>4.0.0</modelVersion></project>\n");
    expect(extractRepoUrls(bare, "maven")).toEqual(["https://repo.maven.apache.org/maven2"]);
  });
});

describe("versionInMetadata", () => {
  const metadata = [
    "<metadata>",
    "  <groupId>org.eclipse.jetty</groupId>",
    "  <artifactId>jetty-http</artifactId>",
    "  <versioning>",
    "    <latest>11.0.24</latest>",
    "    <release>11.0.24</release>",
    "    <versions><version>11.0.23</version><version>11.0.24</version></versions>",
    "  </versioning>",
    "</metadata>",
    "",
  ].join("\n");

  it("finds a published version in <versions>", () => {
    expect(versionInMetadata(metadata, "11.0.23")).toBe(true);
  });

  it("returns false for a version absent from fetched metadata", () => {
    expect(versionInMetadata(metadata, "11.0.29")).toBe(false);
  });

  it("returns null when the document has no <versions> element (fetch failure)", () => {
    expect(versionInMetadata("<error>404 Not Found</error>", "11.0.29")).toBeNull();
    expect(versionInMetadata("", "11.0.29")).toBeNull();
  });
});

describe("extractMavenUnresolved", () => {
  it("parses the 'could not be resolved' artifact list and stops at the reason text", () => {
    const output = [
      "[ERROR] Failed to execute goal on project sample-app: Could not resolve dependencies for project com.example:sample-app:jar:0.0.1-SNAPSHOT:",
      "The following artifacts could not be resolved: org.eclipse.jetty:jetty-http:jar:11.0.29, org.eclipse.jetty:jetty-security:jar:11.0.31:",
      "  org.eclipse.jetty:jetty-http:jar:11.0.29 was not found in https://repo.maven.apache.org/maven2 during a previous attempt.",
    ].join("\n");
    expect(extractMavenUnresolved(output)).toEqual([
      "org.eclipse.jetty:jetty-http@11.0.29",
      "org.eclipse.jetty:jetty-security@11.0.31",
    ]);
  });

  it("parses per-artifact 'was not found in' lines and dedupes", () => {
    const output = [
      "[WARNING] The POM for org.eclipse.jetty:jetty-http:jar:11.0.29 is missing, no dependency information available",
      "org.eclipse.jetty:jetty-http:jar:11.0.29 was not found in https://repo.maven.apache.org/maven2 during a previous attempt.",
      "org.eclipse.jetty:jetty-http:jar:11.0.29 was not found in http://mirror.example.com/nexus during a previous attempt.",
    ].join("\n");
    expect(extractMavenUnresolved(output)).toEqual(["org.eclipse.jetty:jetty-http@11.0.29"]);
  });

  it("returns empty for clean dependency:tree output", () => {
    const output = [
      "[INFO] Scanning for projects...",
      "[INFO] --- dependency:3.6.1:tree (default-cli) @ sample-app ---",
      "[INFO] com.example:sample-app:jar:0.0.1-SNAPSHOT",
      "[INFO] +- org.eclipse.jetty:jetty-http:jar:11.0.24:compile",
      "[INFO] \\-- com.fasterxml.jackson.core:jackson-core:jar:2.21.7:compile",
    ].join("\n");
    expect(extractMavenUnresolved(output)).toEqual([]);
  });
});
