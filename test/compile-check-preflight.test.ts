import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { extractBuildFailureDetail, mavenRequiredJavaRelease, parseJavaMajorVersion } from "../cli/fix.ts";

function withTempFile(name: string, content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-preflight-"));
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const MAVEN_JDK_MISMATCH_LOG = [
  "[INFO] --- maven-compiler-plugin:3.13.0:testCompile (default-testCompile) @ demo-app ---",
  "[ERROR] COMPILATION ERROR :",
  "[ERROR] error: release version 25 not supported",
  "[INFO] ------------------------------------------------------------------------",
  "[INFO] BUILD FAILURE",
  "[INFO] ------------------------------------------------------------------------",
  "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.13.0:testCompile (default-testCompile) on project demo-app: Fatal error compiling: release version 25 not supported -> [Help 1]",
  "[ERROR]",
  "[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.",
  "[ERROR] Re-run Maven using the -X switch to enable full debug logging.",
  "[ERROR]",
  "[ERROR] For more information about the errors and possible solutions, please read the following articles:",
  "[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoExecutionException",
].join("\n");

describe("extractBuildFailureDetail", () => {
  it("leads with the Failed-to-execute-goal line and keeps its concrete error", () => {
    const detail = extractBuildFailureDetail(MAVEN_JDK_MISMATCH_LOG);
    expect(detail).toContain("Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin");
    expect(detail).toContain("release version 25 not supported");
  });

  it("drops the standalone [Help N] footer lines", () => {
    const detail = extractBuildFailureDetail(MAVEN_JDK_MISMATCH_LOG);
    expect(detail).not.toContain("cwiki.apache.org");
    expect(detail).not.toContain("For more information about the errors");
    expect(detail).not.toContain("To see the full stack trace");
  });

  it("leads with the FAILURE headline for Gradle logs", () => {
    const gradleLog = ["> Task :compileJava FAILED", "error: cannot find symbol", "", "FAILURE: Build failed with an exception.", "", "* What went wrong:", "Execution failed for task ':compileJava'."].join("\n");
    const detail = extractBuildFailureDetail(gradleLog);
    expect(detail).toContain("Execution failed for task");
  });

  it("falls back to error lines when there is no build headline", () => {
    const tscLog = ["src/App.ts(12,5): error TS2304: Cannot find name 'Foo'.", "npm ERR! code ELIFECYCLE"].join("\n");
    const detail = extractBuildFailureDetail(tscLog);
    expect(detail).toContain("Cannot find name 'Foo'");
  });

  it("returns empty for blank input", () => {
    expect(extractBuildFailureDetail("")).toBe("");
    expect(extractBuildFailureDetail("\n\n  \n")).toBe("");
  });
});

describe("parseJavaMajorVersion", () => {
  it("parses modern banners", () => {
    expect(parseJavaMajorVersion('openjdk version "21.0.5" 2024-10-15 LTS')).toBe(21);
    expect(parseJavaMajorVersion('openjdk version "25.0.1" 2025-10-21')).toBe(25);
  });

  it("maps legacy 1.x banners to the major version", () => {
    expect(parseJavaMajorVersion('java version "1.8.0_392"')).toBe(8);
  });

  it("returns null without a version banner", () => {
    expect(parseJavaMajorVersion("java was not found")).toBeNull();
    expect(parseJavaMajorVersion("")).toBeNull();
  });
});

const POM_FULL_PLUGIN = `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo-app</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
        <configuration>
          <release>25</release>
          <compilerArgs>
            <arg>-parameters</arg>
          </compilerArgs>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>`;

describe("mavenRequiredJavaRelease", () => {
  it("reads the compiler plugin <release> from a full <plugin> block", () => {
    withTempFile("pom.xml", POM_FULL_PLUGIN, (f) => expect(mavenRequiredJavaRelease(f)).toBe(25));
  });

  it("reads maven.compiler.release resolved through properties", () => {
    const pom = `<project><properties><java.version>17</java.version><maven.compiler.release>\${java.version}</maven.compiler.release></properties></project>`;
    withTempFile("pom.xml", pom, (f) => expect(mavenRequiredJavaRelease(f)).toBe(17));
  });

  it("maps legacy java.version 1.8 to 8", () => {
    const pom = `<project><properties><java.version>1.8</java.version></properties></project>`;
    withTempFile("pom.xml", pom, (f) => expect(mavenRequiredJavaRelease(f)).toBe(8));
  });

  it("prefers the plugin <release> over properties", () => {
    const pom = POM_FULL_PLUGIN.replace("<project>", `<project><properties><java.version>17</java.version></properties>`);
    withTempFile("pom.xml", pom, (f) => expect(mavenRequiredJavaRelease(f)).toBe(25));
  });

  it("ignores non-numeric values", () => {
    const pom = `<project><properties><maven.compiler.release>latest</maven.compiler.release></properties></project>`;
    withTempFile("pom.xml", pom, (f) => expect(mavenRequiredJavaRelease(f)).toBeNull());
  });

  it("returns null when nothing is declared or the pom is missing", () => {
    withTempFile("pom.xml", `<project><artifactId>demo-app</artifactId></project>`, (f) => expect(mavenRequiredJavaRelease(f)).toBeNull());
    expect(mavenRequiredJavaRelease(path.join(os.tmpdir(), "no-such-pom-42.xml"))).toBeNull();
  });
});
