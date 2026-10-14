import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseBuildGradleDirect } from "../src/lib/parse-lockfile.ts";

describe("parseBuildGradleDirect (quoted coordinate idioms)", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-gradle-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("resolves fully-quoted literals, ${var} versions, paren and platform forms", () => {
    const file = path.join(dir, "build.gradle");
    fs.writeFileSync(
      file,
      [
        'plugins { id "java" }',
        "",
        'def log4j_version = "2.25.5"',
        "",
        "dependencies {",
        '    implementation "com.fasterxml.jackson.core:jackson-databind:2.21.4"',
        '    implementation("org.apache.commons:commons-lang3:3.17.0")',
        '    testImplementation "org.apache.logging.log4j:log4j-core:${log4j_version}"',
        '    implementation platform("org.springframework.boot:spring-boot-dependencies:3.4.0")',
        "}",
        "",
      ].join("\n"),
    );

    const result = parseBuildGradleDirect(file);
    const found = new Map(result.packages.map((p) => [p.name, p.version]));

    // Plain quoted literal
    expect(found.get("com.fasterxml.jackson.core:jackson-databind")).toBe("2.21.4");
    // Parenthesized form — only the quoted pass recovers these
    expect(found.get("org.apache.commons:commons-lang3")).toBe("3.17.0");
    expect(found.get("org.springframework.boot:spring-boot-dependencies")).toBe("3.4.0");
    // ${var} version resolved via declared def (quoted pass)
    expect(
      result.packages.some(
        (p) => p.name === "org.apache.logging.log4j:log4j-core" && p.version === "2.25.5",
      ),
    ).toBe(true);
  });

  it("skips coordinates listed in the excludes block", () => {
    const file = path.join(dir, "build-exclude.gradle");
    fs.writeFileSync(
      file,
      [
        "dependencies {",
        '    implementation "com.google.guava:guava:33.4.0-jre"',
        "}",
        "",
        "configurations.all {",
        '    exclude group: "com.google.guava", module: "guava"',
        "}",
        "",
      ].join("\n"),
    );

    const result = parseBuildGradleDirect(file);
    expect(result.packages.find((p) => p.name === "com.google.guava:guava")).toBeUndefined();
  });

  it("resolves camelCase and uppercase version variable names", () => {
    const file = path.join(dir, "build-camelcase.gradle");
    fs.writeFileSync(
      file,
      [
        'def log4jVersion = "2.17.1"',
        'def netty_VERSION = "4.2.18.Final"',
        "",
        "dependencies {",
        '    implementation "org.apache.logging.log4j:log4j-core:${log4jVersion}"',
        '    implementation "io.netty:netty-codec-http2:${netty_VERSION}"',
        "}",
        "",
      ].join("\n"),
    );

    const result = parseBuildGradleDirect(file);
    const found = new Map(result.packages.map((p) => [p.name, p.version]));
    expect(found.get("org.apache.logging.log4j:log4j-core")).toBe("2.17.1");
    expect(found.get("io.netty:netty-codec-http2")).toBe("4.2.18.Final");
  });

  it("does not swallow following deps on an unquoted concat line (api 'g:a:' + var)", () => {
    const file = path.join(dir, "build-concat.gradle");
    fs.writeFileSync(
      file,
      [
        "dependencies {",
        "    api 'com.example:lib:' + libVersion",
        "    implementation 'org.other:thing:1.0'",
        "}",
        "",
      ].join("\n"),
    );

    const result = parseBuildGradleDirect(file);
    // The following dep must be recovered (old regex swallowed it into a garbage match)
    expect(result.packages.find((p) => p.name === "org.other:thing")?.version).toBe("1.0");
    // No garbage entry for com.example:lib with a multi-line version
    expect(result.packages.find((p) => p.name === "com.example:lib")).toBeUndefined();
    // No version may contain whitespace (the old bug produced a multi-line capture)
    expect(result.packages.every((p) => !/\s/.test(p.version ?? ""))).toBe(true);
  });

  it("resolves concatenated versions ('g:a:' + var) when the variable is declared", () => {
    const file = path.join(dir, "build-concat-resolved.gradle");
    fs.writeFileSync(
      file,
      [
        'def spring_cloud_version = "2025.1.3"',
        'def rest_assured_version = "5.5.5"',
        'def single_quote_version = "9.9.9"',
        "",
        "dependencies {",
        '    implementation(enforcedPlatform("org.springframework.cloud:spring-cloud-dependencies:" + spring_cloud_version))',
        '    testImplementation "io.rest-assured:rest-assured-all:" + rest_assured_version',
        "    implementation 'com.example:single:' + single_quote_version",
        "    api 'com.example:lib:' + undefinedVar",
        "}",
        "",
      ].join("\n"),
    );

    const result = parseBuildGradleDirect(file);
    const found = new Map(result.packages.map((p) => [p.name, p.version]));
    expect(found.get("org.springframework.cloud:spring-cloud-dependencies")).toBe("2025.1.3");
    expect(found.get("io.rest-assured:rest-assured-all")).toBe("5.5.5");
    expect(found.get("com.example:single")).toBe("9.9.9");
    // Unresolvable variable still skipped
    expect(result.packages.find((p) => p.name === "com.example:lib")).toBeUndefined();
  });
});
