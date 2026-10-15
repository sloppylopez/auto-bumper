import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { GRADLE_MARKER_BEGIN, GRADLE_MARKER_END } from "../src/lib/brand.ts";
import { applyBumps, applyRenames, hasEnforcedPlatform, readDeclaredVersion } from "../src/lib/gradle-editor.ts";

function withTempGradle(content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-gradle-"));
  const filePath = path.join(dir, "build.gradle");
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) {
    count++;
    idx += needle.length;
  }
  return count;
}

function readGradle(filePath: string): string {
  return fs.readFileSync(filePath, "utf-8");
}

describe("applyBumps", () => {
  it("bumps a literal group:artifact:version dependency", () => {
    withTempGradle(
      `dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:2.21.4"
}`,
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "com.fasterxml.jackson.core:jackson-databind",
          targetVersion: "2.21.5",
          because: ["GHSA-test"],
        }]);
        expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-databind");
        const content = readGradle(filePath);
        expect(content).toContain("com.fasterxml.jackson.core:jackson-databind:2.21.5");
        expect(content).not.toContain(":2.21.4");
      },
    );
  });

  it("bumps via shared def version variable", () => {
    withTempGradle(
      `def jackson_version = "2.21.4"

dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:\${jackson_version}"
}`,
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "com.fasterxml.jackson.core:jackson-databind",
          targetVersion: "2.21.5",
          because: ["GHSA-test"],
        }]);
        expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-databind");
        const content = readGradle(filePath);
        expect(content).toContain('jackson_version = "2.21.5"');
        expect(result.warnings.some(w => w.includes("shared variable"))).toBe(true);
      },
    );
  });

  it("appends managed constraints for transitive deps and stays idempotent on re-run", () => {
    withTempGradle("plugins { id 'java' }\n", filePath => {
      const bump = {
        packageName: "com.example:transitive-lib",
        targetVersion: "2.0.0",
        because: ["CVE-TEST"],
      };

      applyBumps(filePath, [bump]);
      const afterFirst = readGradle(filePath);
      expect(afterFirst).toContain(GRADLE_MARKER_BEGIN);
      expect(afterFirst).toContain("com.example:transitive-lib:2.0.0");

      applyBumps(filePath, [bump]);
      const afterSecond = readGradle(filePath);
      expect(countOccurrences(afterSecond, GRADLE_MARKER_BEGIN)).toBe(1);
      expect(countOccurrences(afterSecond, GRADLE_MARKER_END)).toBe(1);
      expect(afterSecond).toContain("com.example:transitive-lib:2.0.0");
    });
  });
});

describe("applyRenames", () => {
  it("renames com.fasterxml jackson coords to tools.jackson on literal dep", () => {
    withTempGradle(
      `dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:2.21.4"
}`,
      filePath => {
        const result = applyRenames(filePath, [{
          fromPackage: "com.fasterxml.jackson.core:jackson-databind",
          toPackage: "tools.jackson.core:jackson-databind",
          targetVersion: "3.1.4",
          because: ["GHSA-5jmj-h7xm-6q6v"],
        }]);
        expect(result.direct.length).toBe(1);
        const content = readGradle(filePath);
        expect(content).toContain("tools.jackson.core:jackson-databind:3.1.4");
        expect(content).not.toContain("com.fasterxml.jackson.core:jackson-databind");
      },
    );
  });

  it("renames coords and bumps shared version variable", () => {
    withTempGradle(
      `def jackson_version = "2.21.4"

dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:\${jackson_version}"
}`,
      filePath => {
        applyRenames(filePath, [{
          fromPackage: "com.fasterxml.jackson.core:jackson-databind",
          toPackage: "tools.jackson.core:jackson-databind",
          targetVersion: "3.1.4",
          because: ["GHSA-5jmj-h7xm-6q6v"],
        }]);
        const content = readGradle(filePath);
        expect(content).toContain('jackson_version = "3.1.4"');
        expect(content).toContain("tools.jackson.core:jackson-databind");
        expect(content).not.toContain("com.fasterxml.jackson.core:jackson-databind");
      },
    );
  });

  it("adds global exclude for Jackson 3 migration by default", () => {
    withTempGradle(
      `dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:2.21.4"
}`,
      filePath => {
        applyRenames(filePath, [{
          fromPackage: "com.fasterxml.jackson.core:jackson-databind",
          toPackage: "tools.jackson.core:jackson-databind",
          targetVersion: "3.1.4",
          because: ["GHSA-5jmj-h7xm-6q6v"],
        }]);
        const content = readGradle(filePath);
        expect(content).toMatch(/exclude\s+group:\s*['"]com\.fasterxml\.jackson\.core['"]/);
      },
    );
  });

  it("adds global exclude when excludeOldCoordinates is true", () => {
    withTempGradle(
      `dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:2.21.4"
}`,
      filePath => {
        applyRenames(filePath, [{
          fromPackage: "com.fasterxml.jackson.core:jackson-databind",
          toPackage: "tools.jackson.core:jackson-databind",
          targetVersion: "3.1.4",
          because: ["GHSA-5jmj-h7xm-6q6v"],
        }], { excludeOldCoordinates: true });
        const content = readGradle(filePath);
        expect(content).toMatch(/exclude\s+group:\s*['"]com\.fasterxml\.jackson\.core['"]/);
      },
    );
  });

  it("completes partial Jackson migration: BOM, bare core dep, managed constraints", () => {
    withTempGradle(
      `def jackson_version = "3.1.4"

dependencyManagement {
    imports {
        mavenBom "com.fasterxml.jackson:jackson-bom:\${jackson_version}"
    }
}

dependencies {
    implementation("tools.jackson.core:jackson-databind:\${jackson_version}")
    implementation("com.fasterxml.jackson.core:jackson-core")
}

// auto-bumper:begin managed constraints (auto-generated, do not edit)
dependencies {
    constraints {
        implementation('com.fasterxml.jackson.core:jackson-core:2.21.1') { because 'GHSA-72hv' }
        implementation('com.fasterxml.jackson.core:jackson-databind:2.21.4') { because 'GHSA-other' }
    }
}
// auto-bumper:end
`,
      filePath => {
        const renames = [
          {
            fromPackage: "com.fasterxml.jackson.core:jackson-annotations",
            toPackage: "tools.jackson.core:jackson-annotations",
            targetVersion: "3.1.4",
            because: ["GHSA-5jmj"],
          },
          {
            fromPackage: "com.fasterxml.jackson.core:jackson-core",
            toPackage: "tools.jackson.core:jackson-core",
            targetVersion: "3.1.4",
            because: ["GHSA-5jmj"],
          },
          {
            fromPackage: "com.fasterxml.jackson.core:jackson-databind",
            toPackage: "tools.jackson.core:jackson-databind",
            targetVersion: "3.1.4",
            because: ["GHSA-5jmj"],
          },
        ];
        const result = applyRenames(filePath, renames);
        const content = readGradle(filePath);
        expect(content).toContain('tools.jackson.core:jackson-core');
        expect(content).not.toContain("com.fasterxml.jackson.core:jackson-core");
        expect(content).not.toContain("com.fasterxml.jackson:jackson-bom");
        expect(content).not.toContain("com.fasterxml.jackson.core:jackson-databind:2.21.4");
        expect(content).toContain("tools.jackson.core:jackson-databind:3.1.4");
        expect(result.warnings.some(w => w.includes("jackson-bom"))).toBe(true);
      },
    );
  });

  it("migrates BOM-managed jackson setup with full sibling bundle", () => {
    withTempGradle(
      `def jackson_version = "2.21.4"

dependencyManagement {
    imports {
        mavenBom "com.fasterxml.jackson:jackson-bom:\${jackson_version}"
    }
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:\${jackson_version}")
    implementation("com.fasterxml.jackson.core:jackson-core")
}`,
      filePath => {
        const renames = [
          {
            fromPackage: "com.fasterxml.jackson.core:jackson-core",
            toPackage: "tools.jackson.core:jackson-core",
            targetVersion: "3.1.4",
            because: ["GHSA-5jmj-h7xm-6q6v"],
          },
          {
            fromPackage: "com.fasterxml.jackson.core:jackson-databind",
            toPackage: "tools.jackson.core:jackson-databind",
            targetVersion: "3.1.4",
            because: ["GHSA-5jmj-h7xm-6q6v"],
          },
        ];
        applyRenames(filePath, renames);
        const content = readGradle(filePath);
        expect(content).toContain('jackson_version = "3.1.4"');
        expect(content).toContain("tools.jackson.core:jackson-databind");
        expect(content).toContain("tools.jackson.core:jackson-core");
        expect(content).not.toContain("com.fasterxml.jackson.core:jackson-core");
        expect(content).not.toContain("com.fasterxml.jackson:jackson-bom");
        expect(content).toContain("com.fasterxml.jackson.core:jackson-annotations:2.21");
        expect(content).toContain("tools.jackson.core:jackson-core:3.1.4");
        expect(content).toContain("tools.jackson.core:jackson-databind:3.1.4");
        expect(content).not.toMatch(/exclude group: 'com\.fasterxml\.jackson\.core', module: 'jackson-annotations'/);
        expect(content).toMatch(/exclude group: 'com\.fasterxml\.jackson\.core', module: 'jackson-core'/);
        expect(content).toMatch(/exclude group: 'com\.fasterxml\.jackson\.core', module: 'jackson-databind'/);
      },
    );
  });

  describe("hasEnforcedPlatform", () => {
    it("detects enforcedPlatform()", () => {
      expect(hasEnforcedPlatform('implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.5.0"))')).toBe(true);
    });

    it("detects platform()", () => {
      expect(hasEnforcedPlatform('implementation(platform("io.spring.platform:platform-bom:1.0.0.RELEASE"))')).toBe(true);
    });

    it("detects mavenBom", () => {
      expect(hasEnforcedPlatform('mavenBom "org.springframework.cloud:spring-cloud-dependencies:2025.0.0"')).toBe(true);
    });

    it("detects the Spring Boot plugin", () => {
      expect(hasEnforcedPlatform("id 'org.springframework.boot' version '3.3.0'")).toBe(true);
      expect(hasEnforcedPlatform('id("io.spring.dependency-management") version "1.1.6"')).toBe(true);
    });

    it("returns false when no BOM present", () => {
      expect(hasEnforcedPlatform('dependencies {\n    implementation "commons-io:commons-io:2.19.0"\n}')).toBe(false);
    });
  });
});
