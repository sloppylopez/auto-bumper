import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { GRADLE_MARKER_BEGIN, GRADLE_MARKER_END } from "../src/lib/brand.ts";
import { applyBumps, applyRenames, detectGradlePlatform, findStaleManagedPins, hasEnforcedPlatform, readDeclaredVersion, removeManagedPin } from "../src/lib/gradle-editor.ts";

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

  it("applies an approved downgrade below the declared version and overrides stale higher pins", () => {
    withTempGradle(
      `def jaxb_version = "4.0.9"

dependencies {
    implementation platform("org.springframework.boot:spring-boot-dependencies:3.5.0")
}

configurations.all {
    resolutionStrategy {
        force "org.glassfish.jaxb:jaxb-core:\${jaxb_version}"
        force "org.glassfish.jaxb:jaxb-runtime:\${jaxb_version}"
    }
}`,
      filePath => {
        // A previous run pinned a higher release in the managed block.
        applyBumps(filePath, [{
          packageName: "org.glassfish.jaxb:jaxb-core",
          targetVersion: "4.1.0",
          because: ["CVE-OLD"],
        }]);
        expect(readGradle(filePath)).toContain("org.glassfish.jaxb:jaxb-core:4.1.0");

        const result = applyBumps(filePath, [{
          packageName: "org.glassfish.jaxb:jaxb-core",
          targetVersion: "3.0.2",
          because: ["CVE-2026-92877"],
          isDowngrade: true,
        }]);
        expect(result.constrained).toContain("org.glassfish.jaxb:jaxb-core");
        const content = readGradle(filePath);
        // The downgrade must not be raised back to the declared 4.0.9 nor masked by the stale pin.
        expect(content).toContain("org.glassfish.jaxb:jaxb-core:3.0.2");
        expect(content).not.toContain("org.glassfish.jaxb:jaxb-core:4.1.0");
        // Shared-variable siblings are not dragged down with the downgrade.
        expect(content).not.toContain("org.glassfish.jaxb:jaxb-runtime:3.0.2");
      },
    );
  });
});

const QUARKUS_BUILD = [
  "plugins { id 'io.quarkus' }",
  "",
  "dependencies {",
  '    enforcedPlatform("${quarkusPlatformGroupId}:${quarkusPlatformArtifactId}:${quarkusPlatformVersion}")',
  "}",
].join("\n");

const QUARKUS_PROPS = [
  "quarkusPluginId=io.quarkus",
  "quarkusPluginVersion=3.28.5",
  "quarkusPlatformGroupId=io.quarkus.platform",
  "quarkusPlatformArtifactId=quarkus-bom",
  "quarkusPlatformVersion=3.28.5",
].join("\n");

function withTempGradleAndProperties(build: string, props: string | null, run: (filePath: string, propsPath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-gradle-"));
  const filePath = path.join(dir, "build.gradle");
  const propsPath = path.join(dir, "gradle.properties");
  fs.writeFileSync(filePath, build, "utf-8");
  if (props !== null) fs.writeFileSync(propsPath, props, "utf-8");
  try {
    run(filePath, propsPath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("platform policy", () => {
  it("detects a property-based Quarkus platform coordinate", () => {
    withTempGradleAndProperties(QUARKUS_BUILD, QUARKUS_PROPS, (filePath, propsPath) => {
      expect(detectGradlePlatform(filePath)).toEqual({
        group: "io.quarkus.platform",
        artifact: "quarkus-bom",
        version: "3.28.5",
        property: "quarkusPlatformVersion",
      });
      expect(fs.existsSync(propsPath)).toBe(true);
    });
  });

  it("detects an inline literal platform coordinate and returns null when unresolvable", () => {
    withTempGradle(
      'dependencies {\n    implementation platform("org.springframework.boot:spring-boot-dependencies:3.2.5")\n}',
      filePath => {
        expect(detectGradlePlatform(filePath)).toEqual({
          group: "org.springframework.boot",
          artifact: "spring-boot-dependencies",
          version: "3.2.5",
        });
      },
    );
    withTempGradle('dependencies {\n    implementation platform("com.example:bom:${unknownVar}")\n}', filePath => {
      expect(detectGradlePlatform(filePath)).toBeNull();
    });
    withTempGradle("plugins { id 'java' }\n", filePath => {
      expect(detectGradlePlatform(filePath)).toBeNull();
    });
  });

  it("bumps the whole Quarkus platform when a BOM-managed fix crosses the minor line", () => {
    withTempGradleAndProperties(QUARKUS_BUILD, QUARKUS_PROPS, (filePath, propsPath) => {
      const result = applyBumps(filePath, [{
        packageName: "io.quarkus:quarkus-vertx-http",
        targetVersion: "3.33.2.1",
        because: ["GHSA-qcxp-gm7m-4j5v"],
        installedVersion: "3.28.5",
      }]);
      const props = readGradle(propsPath);
      expect(props).toContain("quarkusPlatformVersion=3.33.2.1");
      // Quarkus plugin stays in sync with the platform.
      expect(props).toContain("quarkusPluginVersion=3.33.2.1");
      expect(result.direct.some(e => e.startsWith("io.quarkus:quarkus-vertx-http:"))).toBe(true);
      expect(result.appliedTargets?.["io.quarkus:quarkus-vertx-http"]).toBe("3.33.2.1");
      // No single-artifact constraint or force pin for the BOM-managed artifact.
      const content = readGradle(filePath);
      expect(content).not.toContain("io.quarkus:quarkus-vertx-http");
      expect(result.warnings.some(w => w.includes("Bumped io.quarkus.platform:quarkus-bom 3.28.5 → 3.33.2.1"))).toBe(true);
    });
  });

  it("keeps same-minor family fixes on the pin path and leaves the platform untouched", () => {
    withTempGradleAndProperties(QUARKUS_BUILD, QUARKUS_PROPS, (filePath, propsPath) => {
      const result = applyBumps(filePath, [{
        packageName: "io.quarkus:quarkus-rest",
        targetVersion: "3.28.9",
        because: ["GHSA-test"],
        installedVersion: "3.28.5",
      }]);
      expect(result.constrained).toContain("io.quarkus:quarkus-rest");
      const props = readGradle(propsPath);
      expect(props).toContain("quarkusPlatformVersion=3.28.5");
    });
  });

  it("skips non-family cross-minor fixes under an identified platform instead of desynchronizing siblings", () => {
    withTempGradleAndProperties(QUARKUS_BUILD, QUARKUS_PROPS, (filePath, propsPath) => {
      const result = applyBumps(filePath, [{
        packageName: "io.netty:netty-codec-http",
        targetVersion: "4.2.0.Final",
        because: ["GHSA-test"],
        installedVersion: "4.1.115.Final",
      }]);
      expect(result.constrained).not.toContain("io.netty:netty-codec-http");
      expect(result.forced).not.toContain("io.netty:netty-codec-http");
      const content = readGradle(filePath);
      expect(content).not.toContain("io.netty:netty-codec-http");
      expect(result.warnings.some(w => w.includes("crosses a minor line"))).toBe(true);
      const props = readGradle(propsPath);
      expect(props).toContain("quarkusPlatformVersion=3.28.5");
    });
  });

  it("converges multiple family fixes on the highest platform version", () => {
    withTempGradleAndProperties(QUARKUS_BUILD, QUARKUS_PROPS, (filePath, propsPath) => {
      const result = applyBumps(filePath, [
        { packageName: "io.quarkus:quarkus-vertx-http", targetVersion: "3.33.2.1", because: ["GHSA-a"] },
        { packageName: "io.quarkus:quarkus-hibernate-orm", targetVersion: "3.34.0", because: ["GHSA-b"] },
      ]);
      const props = readGradle(propsPath);
      expect(props).toContain("quarkusPlatformVersion=3.34.0");
      expect(result.direct.filter(e => e.includes("via io.quarkus.platform:quarkus-bom")).length).toBe(2);
    });
  });

  it("skips cross-minor fixes when artifact versions do not map to platform releases", () => {
    withTempGradle(
      'dependencies {\n    implementation platform("org.springframework.boot:spring-boot-dependencies:3.2.5")\n}',
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "org.springframework:spring-web",
          targetVersion: "6.2.0",
          because: ["GHSA-test"],
          installedVersion: "6.1.5",
        }]);
        expect(result.direct).not.toContain("org.springframework:spring-web");
        expect(result.constrained).not.toContain("org.springframework:spring-web");
        expect(result.forced).not.toContain("org.springframework:spring-web");
        const content = readGradle(filePath);
        expect(content).not.toContain("org.springframework:spring-web");
        expect(result.warnings.some(w => w.includes("bump the platform/BOM manually"))).toBe(true);
      },
    );
  });

  it("skips cross-minor BOM-managed fixes when the platform version cannot be identified", () => {
    withTempGradle(
      "plugins {\n    id 'org.springframework.boot' version '3.2.5'\n}\n",
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "org.apache.tomcat.embed:tomcat-embed-core",
          targetVersion: "10.2.0",
          because: ["GHSA-test"],
          installedVersion: "10.1.20",
        }]);
        expect(result.constrained).not.toContain("org.apache.tomcat.embed:tomcat-embed-core");
        expect(result.forced).not.toContain("org.apache.tomcat.embed:tomcat-embed-core");
        const content = readGradle(filePath);
        expect(content).not.toContain("tomcat-embed-core");
        expect(result.warnings.some(w => w.includes("crosses a minor line"))).toBe(true);
      },
    );
  });

  it("still force-pins same-minor BOM-managed fixes when the platform version cannot be identified", () => {
    withTempGradle(
      "plugins {\n    id 'org.springframework.boot' version '3.2.5'\n}\n",
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "org.apache.tomcat.embed:tomcat-embed-core",
          targetVersion: "10.1.42",
          because: ["GHSA-test"],
          installedVersion: "10.1.20",
        }]);
        expect(result.forced).toContain("org.apache.tomcat.embed:tomcat-embed-core");
      },
    );
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

describe("applyBumps BOM-aware cleanup", () => {
  const bomMap = new Map<string, string>([
    ["io.netty:netty-codec-http2", "4.1.139"],
    ["io.netty:netty-handler", "4.1.139"],
    ["io.netty:netty-resolver-dns", "4.1.139"],
    ["com.example:fresh-lib", "2.0.0"],
    ["org.glassfish.jaxb:jaxb-core", "4.0.8"],
  ]);

  const ENFORCED_FILE = `dependencies {
    implementation(enforcedPlatform("io.quarkus.platform:quarkus-bom:3.33.4.1"))
    implementation "org.slf4j:slf4j-api:2.0.16"
}
`;

  function seed(filePath: string, bumps: Array<{ pkg: string; version: string }>): void {
    applyBumps(filePath, bumps.map(b => ({ packageName: b.pkg, targetVersion: b.version, because: ["GHSA-test"] })));
  }

  it("drops stale constraint and force pins, keeps fresh ones", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [
        { pkg: "io.netty:netty-codec-http2", version: "4.1.136" },
        { pkg: "io.netty:netty-handler", version: "4.1.137" },
        { pkg: "com.example:fresh-lib", version: "3.0.0" },
      ]);
      expect(readGradle(filePath)).toContain(GRADLE_MARKER_BEGIN);

      const result = applyBumps(filePath, [], [], bomMap);
      expect(result.droppedStale).toEqual([
        "io.netty:netty-codec-http2@4.1.136",
        "io.netty:netty-handler@4.1.137",
      ]);
      const content = readGradle(filePath);
      expect(content).not.toContain("4.1.136");
      expect(content).not.toContain("4.1.137");
      expect(content).toContain("com.example:fresh-lib:3.0.0");
      expect(result.warnings.some(w => w.includes("dropped stale pin io.netty:netty-codec-http2@4.1.136"))).toBe(true);
    });
  });

  it("is a byte-identical no-op when no pin is stale", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [{ pkg: "com.example:fresh-lib", version: "3.0.0" }]);
      const before = readGradle(filePath);

      const result = applyBumps(filePath, [], [], bomMap);
      expect(result.droppedStale).toBeUndefined();
      expect(readGradle(filePath)).toBe(before);
    });
  });

  it("removes the managed block entirely when every pin is stale", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [
        { pkg: "io.netty:netty-codec-http2", version: "4.1.136" },
        { pkg: "io.netty:netty-resolver-dns", version: "4.1.135" },
      ]);

      const result = applyBumps(filePath, [], [], bomMap);
      expect(result.droppedStale).toHaveLength(2);
      const content = readGradle(filePath);
      expect(content).not.toContain(GRADLE_MARKER_BEGIN);
      expect(content).not.toContain(GRADLE_MARKER_END);
    });
  });

  it("skips new pins at or below the BOM-managed version", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      const before = readGradle(filePath);
      const result = applyBumps(filePath, [
        { packageName: "io.netty:netty-handler", targetVersion: "4.1.138", because: ["GHSA-x"] },
      ], [], bomMap);
      expect(result.warnings.some(w => w.includes("pin would force a downgrade"))).toBe(true);
      expect(readGradle(filePath)).toBe(before);
    });
  });

  it("keeps new pins above the BOM-managed version", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "io.netty:netty-handler", targetVersion: "4.1.140", because: ["GHSA-y"] },
      ], [], bomMap);
      expect(result.warnings.some(w => w.includes("skipped"))).toBe(false);
      expect(readGradle(filePath)).toContain("io.netty:netty-handler:4.1.140");
    });
  });

  it("keeps explicit downgrades below the BOM-managed version", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "io.netty:netty-handler", targetVersion: "4.1.130", because: ["GHSA-z"], isDowngrade: true },
      ], [], bomMap);
      expect(result.warnings.some(w => w.includes("skipped"))).toBe(false);
      expect(readGradle(filePath)).toContain("io.netty:netty-handler:4.1.130");
    });
  });

  it("pins cross-minor fixes whose family has no same-line siblings", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      const guavaBom = new Map<string, string>([
        ["com.google.guava:guava", "33.5.0-jre"],
        ["com.google.guava:failureaccess", "1.0.2"],
        ["com.google.guava:listenablefuture", "9999.0-empty-to-avoid-conflict-with-guava"],
      ]);
      const result = applyBumps(filePath, [
        { packageName: "com.google.guava:guava", targetVersion: "33.7.2-jre", because: ["CVE-2026-102554"], installedVersion: "33.5.0-jre" },
      ], [], guavaBom);
      expect(result.constrained).toContain("com.google.guava:guava");
      expect(result.forced).toContain("com.google.guava:guava");
      expect(readGradle(filePath)).toContain("com.google.guava:guava:33.7.2-jre");
      expect(result.warnings.some(w => w.includes("crosses a minor line"))).toBe(false);
    });
  });

  it("still skips cross-minor fixes when a same-line sibling is BOM-managed", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      const nettyBom = new Map<string, string>([
        ["io.netty:netty-codec-http", "4.1.135.Final"],
        ["io.netty:netty-codec", "4.1.136.Final"],
        ["io.netty:netty-handler", "4.1.137.Final"],
      ]);
      const result = applyBumps(filePath, [
        { packageName: "io.netty:netty-codec-http", targetVersion: "4.2.0.Final", because: ["GHSA-test"], installedVersion: "4.1.135.Final" },
      ], [], nettyBom);
      expect(result.constrained).not.toContain("io.netty:netty-codec-http");
      expect(result.forced).not.toContain("io.netty:netty-codec-http");
      expect(readGradle(filePath)).not.toContain("io.netty:netty-codec-http");
      expect(result.warnings.some(w => w.includes("crosses a minor line"))).toBe(true);
    });
  });

  it("is idempotent across repeated cleanup runs", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [{ pkg: "io.netty:netty-codec-http2", version: "4.1.136" }]);
      applyBumps(filePath, [], [], bomMap);
      const afterFirst = readGradle(filePath);

      const second = applyBumps(filePath, [], [], bomMap);
      expect(second.droppedStale).toBeUndefined();
      expect(readGradle(filePath)).toBe(afterFirst);
    });
  });

  it("keeps a protected vulnerability-escape pin while dropping other stale pins", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [
        { pkg: "org.glassfish.jaxb:jaxb-core", version: "3.0.2" },
        { pkg: "io.netty:netty-codec-http2", version: "4.1.136" },
      ]);

      const result = applyBumps(filePath, [], [], bomMap, new Set(["org.glassfish.jaxb:jaxb-core"]));
      expect(result.droppedStale).toEqual(["io.netty:netty-codec-http2@4.1.136"]);
      const content = readGradle(filePath);
      expect(content).toContain("org.glassfish.jaxb:jaxb-core:3.0.2");
      expect(content).not.toContain("4.1.136");
    });
  });

  it("drops a stale pin when it is not protected", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [{ pkg: "org.glassfish.jaxb:jaxb-core", version: "3.0.2" }]);

      const result = applyBumps(filePath, [], [], bomMap);
      expect(result.droppedStale).toEqual(["org.glassfish.jaxb:jaxb-core@3.0.2"]);
      expect(readGradle(filePath)).not.toContain("org.glassfish.jaxb:jaxb-core:3.0.2");
    });
  });

  it("keeps the protected pin when new bumps are applied in the same run", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [{ pkg: "org.glassfish.jaxb:jaxb-core", version: "3.0.2" }]);

      applyBumps(filePath, [
        { packageName: "io.netty:netty-handler", targetVersion: "4.1.140", because: ["GHSA-w"] },
      ], [], bomMap, new Set(["org.glassfish.jaxb:jaxb-core"]));
      const content = readGradle(filePath);
      expect(content).toContain("org.glassfish.jaxb:jaxb-core:3.0.2");
      expect(content).toContain("io.netty:netty-handler:4.1.140");
    });
  });

  it("findStaleManagedPins skips protected pins", () => {
    withTempGradle(ENFORCED_FILE, filePath => {
      seed(filePath, [
        { pkg: "org.glassfish.jaxb:jaxb-core", version: "3.0.2" },
        { pkg: "io.netty:netty-codec-http2", version: "4.1.136" },
      ]);

      const stale = findStaleManagedPins(readGradle(filePath), bomMap, new Set(["org.glassfish.jaxb:jaxb-core"]));
      expect(stale).toEqual([{ packageName: "io.netty:netty-codec-http2", version: "4.1.136", bomVersion: "4.1.139" }]);
    });
  });
});
describe("managed block comment preservation", () => {
  it("keeps a human comment above a pin when the managed block is re-rendered", () => {
    withTempGradle(
      `plugins { id 'java' }

dependencies {
    implementation 'com.example:json-schema-validator:2.2.13'
}

${GRADLE_MARKER_BEGIN}
dependencies {
    constraints {
        // Pinned below 2.3.x: json-patch 1.13 is compiled against the 2.0 API and
        // throws NoSuchMethodError under coreutils 1.12.
        implementation('com.networknt:json-schema-validator:2.2.13') { because 'GHSA-json' }
    }
}
${GRADLE_MARKER_END}`,
      filePath => {
        applyBumps(filePath, [{
          packageName: "com.example:other-lib",
          targetVersion: "1.0.1",
          because: ["CVE-TEST"],
        }]);
        const content = readGradle(filePath);
        expect(content).toContain("throws NoSuchMethodError under coreutils 1.12.");
        // The comment must still sit directly above its pin.
        const lines = content.split("\n");
        const pinIdx = lines.findIndex(l => l.includes("com.networknt:json-schema-validator:2.2.13"));
        expect(lines[pinIdx - 1].trim()).toContain("throws NoSuchMethodError under coreutils 1.12.");
      },
    );
  });

  it("drops the comment of a removed pin but keeps the others", () => {
    withTempGradle(
      `${GRADLE_MARKER_BEGIN}
dependencies {
    constraints {
        // Keep old: documents why this stays pinned.
        implementation('com.example:keep-old:1.0.0') { because 'GHSA-keep' }
        // Drop me: this pin is going away.
        implementation('com.example:drop-me:1.0.0') { because 'GHSA-drop' }
    }
}
${GRADLE_MARKER_END}`,
      filePath => {
        expect(removeManagedPin(filePath, "com.example:drop-me")).toBe(true);
        const content = readGradle(filePath);
        expect(content).toContain("documents why this stays pinned.");
        expect(content).not.toContain("this pin is going away.");
        expect(content).toContain("com.example:keep-old:1.0.0");
      },
    );
  });

  it("moves a comment with its renamed coordinate and keeps force pins", () => {
    withTempGradle(
      `${GRADLE_MARKER_BEGIN}
dependencies {
    constraints {
        // Old group is deprecated; new group follows.
        implementation('com.fasterxml.jackson.core:jackson-databind:2.19.0') { because 'GHSA-5jmj' }
    }
}
configurations.all {
    resolutionStrategy {
        force 'com.fasterxml.jackson.core:jackson-databind:2.19.4'
        force 'org.example:sibling-lib:1.2.3'
}
${GRADLE_MARKER_END}`,
      filePath => {
        applyRenames(filePath, [{
          fromPackage: "com.fasterxml.jackson.core:jackson-databind",
          toPackage: "tools.jackson.core:jackson-databind",
          targetVersion: "3.1.4",
          because: ["GHSA-5jmj-h7xm-6q6v"],
        }]);
        const content = readGradle(filePath);
        expect(content).toContain("tools.jackson.core:jackson-databind:3.1.4");
        // The comment follows the pin to its new coordinate...
        const lines = content.split("\n");
        const pinIdx = lines.findIndex(l => l.includes("tools.jackson.core:jackson-databind:3.1.4"));
        expect(lines[pinIdx - 1].trim()).toContain("Old group is deprecated");
        // The renamed package's force pin follows it, raised to the rename target...
        expect(content).toContain("force 'tools.jackson.core:jackson-databind:3.1.4'");
        // ...and an unrelated force pin survives the re-render (regression: renames used to drop all forces).
        expect(content).toContain("force 'org.example:sibling-lib:1.2.3'");
      },
    );
  });

  it("does not report a shared-variable bump when the def already satisfies the target", () => {
    withTempGradle(
      `def pg_version = "42.7.14"

dependencies {
    implementation "org.postgresql:postgresql:\${pg_version}"
}`,
      filePath => {
        const result = applyBumps(filePath, [{
          packageName: "org.postgresql:postgresql",
          targetVersion: "42.7.14",
          because: ["CVE-TEST"],
        }]);
        expect(result.warnings.some(w => w.includes("shared variable"))).toBe(false);
      },
    );
  });
});
