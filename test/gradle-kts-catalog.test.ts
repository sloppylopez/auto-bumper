import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findVersionCatalog, parseVersionCatalog, resolveCatalogAccessor } from "../src/lib/gradle-catalog.ts";
import { applyBumps } from "../src/lib/gradle-editor.ts";
import { parseBuildGradleDirect } from "../src/lib/parse-lockfile.ts";

const CATALOG = `[versions]
jackson = "2.15.0"

[libraries]
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }
netty-handler = { module = "io.netty:netty-handler", version = "4.1.94.Final" }

[bundles]
jackson = ["jackson-core"]
`;

function write(dir: string, rel: string, content: string): string {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf-8");
  return file;
}

describe("findVersionCatalog", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-catalog-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("finds the catalog in the build file's own directory", () => {
    const build = write(dir, "a/build.gradle.kts", "");
    const toml = write(dir, "a/gradle/libs.versions.toml", CATALOG);
    expect(findVersionCatalog(build)).toBe(toml);
  });

  it("walks up a multi-module subproject to the root catalog (settings marker)", () => {
    const build = write(dir, "b/app/lib/build.gradle.kts", "");
    write(dir, "b/settings.gradle.kts", 'rootProject.name = "b"\n');
    const toml = write(dir, "b/gradle/libs.versions.toml", CATALOG);
    expect(findVersionCatalog(build)).toBe(toml);
  });

  it("walks up when the build root is marked by the wrapper instead of a settings file", () => {
    const build = write(dir, "c/app/build.gradle.kts", "");
    write(dir, "c/gradlew.bat", "@echo off\n");
    const toml = write(dir, "c/libs.versions.toml", CATALOG);
    expect(findVersionCatalog(build)).toBe(toml);
  });

  it("stops at an included build's own settings file and does not see the outer catalog", () => {
    const build = write(dir, "d/sub/build.gradle.kts", "");
    write(dir, "d/settings.gradle.kts", 'includeBuild("sub")\n');
    write(dir, "d/gradle/libs.versions.toml", CATALOG);
    write(dir, "d/sub/settings.gradle.kts", 'rootProject.name = "sub"\n');
    expect(findVersionCatalog(build)).toBeNull();
  });

  it("prefers the subproject's own catalog over the root's", () => {
    const build = write(dir, "e/app/build.gradle.kts", "");
    write(dir, "e/settings.gradle.kts", 'rootProject.name = "e"\n');
    write(dir, "e/gradle/libs.versions.toml", CATALOG);
    const own = write(dir, "e/app/gradle/libs.versions.toml", CATALOG);
    expect(findVersionCatalog(build)).toBe(own);
  });

  it("without any build-root marker only the own directory counts", () => {
    const build = write(dir, "f/inner/build.gradle.kts", "");
    write(dir, "f/gradle/libs.versions.toml", CATALOG); // unmarked ancestor — must not be found
    expect(findVersionCatalog(build)).toBeNull();
    const own = write(dir, "f/inner/libs.versions.toml", CATALOG);
    expect(findVersionCatalog(build)).toBe(own);
  });

  it("returns null when no catalog exists", () => {
    const build = write(dir, "g/build.gradle.kts", "");
    write(dir, "g/settings.gradle.kts", 'rootProject.name = "g"\n');
    expect(findVersionCatalog(build)).toBeNull();
  });
});

describe("parseVersionCatalog / resolveCatalogAccessor", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-catalog-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("parses versions, version.ref and inline versions, including multi-line tables", () => {
    const toml = write(
      dir,
      "libs.versions.toml",
      [
        "# comment line",
        "[versions]",
        'jackson = "2.15.0" # trailing comment',
        "",
        "[libraries]",
        'jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version.ref = "jackson" }',
        "multi-line = {",
        '    module = "org.example:thing",',
        '    version = "1.2.3"',
        "}",
        "",
        "[bundles]",
        'jackson = ["jackson-core"]',
      ].join("\n"),
    );
    const catalog = parseVersionCatalog(toml);
    expect(catalog).not.toBeNull();
    expect(catalog!.versions.get("jackson")).toBe("2.15.0");

    const core = resolveCatalogAccessor(catalog!, "jackson.core");
    expect(core?.module).toBe("com.fasterxml.jackson.core:jackson-core");
    expect(core?.version).toBe("2.15.0"); // version.ref dereferenced

    const multi = resolveCatalogAccessor(catalog!, "multi.line");
    expect(multi?.module).toBe("org.example:thing");
    expect(multi?.version).toBe("1.2.3");

    // versions/bundles accessors have no [libraries] entry under those aliases
    expect(resolveCatalogAccessor(catalog!, "versions.jackson")).toBeNull();
    expect(resolveCatalogAccessor(catalog!, "bundles.jackson")).toBeNull();
  });

  it("returns null for a missing file", () => {
    expect(parseVersionCatalog(path.join(dir, "nope.toml"))).toBeNull();
  });
});

describe("applyBumps with version catalogs", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-catalog-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("bumps the root catalog from a multi-module subproject build file (no local pin)", () => {
    const toml = write(dir, "m/gradle/libs.versions.toml", CATALOG);
    write(dir, "m/settings.gradle.kts", 'rootProject.name = "m"\ninclude(":app")\n');
    const build = write(
      dir,
      "m/app/build.gradle.kts",
      ["plugins { java }", "", "dependencies {", "    implementation(libs.jackson.core)", "}", ""].join("\n"),
    );

    const result = applyBumps(build, [
      { packageName: "com.fasterxml.jackson.core:jackson-core", targetVersion: "2.17.0", because: ["GHSA-test"] },
    ]);

    expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-core");
    expect(result.constrained).not.toContain("com.fasterxml.jackson.core:jackson-core");
    const tomlAfter = fs.readFileSync(toml, "utf-8");
    expect(tomlAfter).toContain('jackson = "2.17.0"');
    // no managed block leaked into the subproject build file
    expect(fs.readFileSync(build, "utf-8")).not.toContain("auto-bumper:begin");
  });

  it("bumps inline catalog versions and leaves accessor declarations untouched", () => {
    const toml = write(dir, "n/gradle/libs.versions.toml", CATALOG);
    const build = write(
      dir,
      "n/build.gradle.kts",
      ["plugins { java }", "", "dependencies {", "    implementation(libs.netty.handler)", "}", ""].join("\n"),
    );

    const result = applyBumps(build, [
      { packageName: "io.netty:netty-handler", targetVersion: "4.1.100.Final", because: ["GHSA-test"] },
    ]);

    expect(result.direct).toContain("io.netty:netty-handler");
    expect(fs.readFileSync(toml, "utf-8")).toContain('version = "4.1.100.Final"');
    expect(fs.readFileSync(build, "utf-8")).toContain("implementation(libs.netty.handler)");
  });

  it("rewrites map-style declarations with an unquoted version variable (kotlin)", () => {
    const build = write(
      dir,
      "o/build.gradle.kts",
      [
        'val jacksonVersion = "2.15.0"',
        "",
        "dependencies {",
        '    implementation(group = "com.fasterxml.jackson.core", name = "jackson-databind", version = jacksonVersion)',
        "}",
        "",
      ].join("\n"),
    );

    const result = applyBumps(build, [
      { packageName: "com.fasterxml.jackson.core:jackson-databind", targetVersion: "2.17.0", because: ["GHSA-test"] },
    ]);

    expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-databind");
    const content = fs.readFileSync(build, "utf-8");
    expect(content).toContain('val jacksonVersion = "2.17.0"');
  });

  it("rewrites map-style declarations with an unquoted version variable (groovy)", () => {
    const build = write(
      dir,
      "p/build.gradle",
      [
        'def jackson_version = "2.15.0"',
        "",
        "dependencies {",
        '    implementation group: "com.fasterxml.jackson.core", name: "jackson-databind", version: jackson_version',
        "}",
        "",
      ].join("\n"),
    );

    const result = applyBumps(build, [
      { packageName: "com.fasterxml.jackson.core:jackson-databind", targetVersion: "2.17.0", because: ["GHSA-test"] },
    ]);

    expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-databind");
    const content = fs.readFileSync(build, "utf-8");
    expect(content).toContain('jackson_version = "2.17.0"');
  });
});

describe("parseBuildGradleDirect with version catalogs", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-catalog-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("resolves libs.* accessor dependencies from the catalog", () => {
    write(dir, "s/settings.gradle.kts", 'rootProject.name = "s"\n');
    write(dir, "s/gradle/libs.versions.toml", CATALOG);
    const build = write(
      dir,
      "s/app/build.gradle.kts",
      ["plugins { java }", "", "dependencies {", "    implementation(libs.jackson.core)", "}", ""].join("\n"),
    );

    const result = parseBuildGradleDirect(build);
    expect(result.warnings).toEqual([]);
    const found = new Map(result.packages.map((p) => [p.name, p.version]));
    expect(found.get("com.fasterxml.jackson.core:jackson-core")).toBe("2.15.0");
  });

  it("resolves ${libs.versions.x} version refs in literal coordinates", () => {
    write(dir, "t/settings.gradle.kts", 'rootProject.name = "t"\n');
    write(dir, "t/gradle/libs.versions.toml", CATALOG);
    const build = write(
      dir,
      "t/build.gradle.kts",
      ["dependencies {", '    implementation("com.fasterxml.jackson.core:jackson-core:${libs.versions.jackson}")', "}", ""].join("\n"),
    );

    const result = parseBuildGradleDirect(build);
    expect(result.warnings).toEqual([]);
    const found = new Map(result.packages.map((p) => [p.name, p.version]));
    expect(found.get("com.fasterxml.jackson.core:jackson-core")).toBe("2.15.0");
  });

  it("does not record versions/bundles accessors as dependencies", () => {
    write(dir, "u/settings.gradle.kts", 'rootProject.name = "u"\n');
    write(dir, "u/gradle/libs.versions.toml", CATALOG);
    const build = write(
      dir,
      "u/build.gradle.kts",
      ["dependencies {", "    implementation(libs.bundles.jackson)", "}", ""].join("\n"),
    );

    const result = parseBuildGradleDirect(build);
    // the bundle resolves to its members only via accessor scan of member accessors; a bare
    // bundles accessor itself must not invent a package
    expect(result.packages.some((p) => p.name.includes("bundles"))).toBe(false);
  });
});
