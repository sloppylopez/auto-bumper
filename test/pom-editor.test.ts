import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { POM_MARKER_BEGIN, POM_MARKER_END } from "../src/lib/brand.ts";
import { applyBumps } from "../src/lib/pom-editor.ts";

function withTempPom(content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-pom-"));
  const filePath = path.join(dir, "pom.xml");
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function readPom(filePath: string): string {
  return fs.readFileSync(filePath, "utf-8");
}

/** Version declared by the first dependency block matching group + artifact. */
function versionOf(pom: string, groupId: string, artifactId: string): string | null {
  for (const block of pom.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
    if (!block.includes(`<groupId>${groupId}</groupId>`)) continue;
    if (!block.includes(`<artifactId>${artifactId}</artifactId>`)) continue;
    const m = /<version>([^<]+)<\/version>/.exec(block);
    return m ? m[1] : null;
  }
  return null;
}

const basePom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>email-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <jackson-core.version>2.21.2</jackson-core.version>
        <io-netty-code.version>4.1.133.Final</io-netty-code.version>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>io.quarkus.platform</groupId>
                <artifactId>quarkus-bom</artifactId>
                <version>3.35.4</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-arc</artifactId>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-core</artifactId>
            <version>\${jackson-core.version}</version>
        </dependency>
        <dependency>
            <groupId>io.netty</groupId>
            <artifactId>netty-codec-http</artifactId>
            <version>\${io-netty-code.version}</version>
        </dependency>
        <dependency>
            <groupId>io.netty</groupId>
            <artifactId>netty-handler</artifactId>
            <version>\${io-netty-code.version}</version>
        </dependency>
        <dependency>
            <groupId>org.mozilla</groupId>
            <artifactId>rhino</artifactId>
            <version>1.7.7.2</version>
        </dependency>
    </dependencies>
</project>
`;

describe("applyBumps (Maven pom.xml)", () => {
  it("rewrites a property version declared in a later dependency block", () => {
    withTempPom(basePom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "com.fasterxml.jackson.core:jackson-core", targetVersion: "2.21.7", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-core");
      expect(result.constrained).toHaveLength(0);
      const after = readPom(filePath);
      expect(after).toContain("<jackson-core.version>2.21.7</jackson-core.version>");
      expect(after).not.toContain(POM_MARKER_BEGIN);
    });
  });

  it("rewrites a literal version in the last dependency block", () => {
    withTempPom(basePom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "org.mozilla:rhino", targetVersion: "1.7.14.1", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("org.mozilla:rhino");
      const after = readPom(filePath);
      expect(versionOf(after, "org.mozilla", "rhino")).toBe("1.7.14.1");
    });
  });

  it("takes the max target when several same-group artifacts share one property", () => {
    withTempPom(basePom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "io.netty:netty-handler", targetVersion: "4.1.137.Final", because: ["GHSA-a"] },
        { packageName: "io.netty:netty-codec-http", targetVersion: "4.1.138.Final", because: ["GHSA-b"] },
      ]);
      expect(result.direct).toEqual(
        expect.arrayContaining(["io.netty:netty-handler", "io.netty:netty-codec-http"]),
      );
      const after = readPom(filePath);
      expect(after).toContain("<io-netty-code.version>4.1.138.Final</io-netty-code.version>");
    });
  });

  it("falls back to a pin when the version property is not defined in the pom", () => {
    const pom = basePom.replace(
      "    </dependencies>\n</project>",
      `        <dependency>
            <groupId>org.example</groupId>
            <artifactId>parent-managed</artifactId>
            <version>\${parent.managed.version}</version>
        </dependency>
    </dependencies>
</project>`,
    );
    withTempPom(pom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "org.example:parent-managed", targetVersion: "9.9.9", because: ["GHSA-test"] },
      ]);
      expect(result.constrained).toContain("org.example:parent-managed");
      const after = readPom(filePath);
      const markerRegion = after.split(POM_MARKER_BEGIN)[1]?.split(POM_MARKER_END)[0] ?? "";
      expect(versionOf(markerRegion, "org.example", "parent-managed")).toBe("9.9.9");
    });
  });

  it("does not let an existing marker pin shadow the real declaration", () => {
    const pom = basePom.replace(
      "    </dependencyManagement>",
      `${POM_MARKER_BEGIN}
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-core</artifactId>
    <version>2.21.7</version>
  </dependency>
${POM_MARKER_END}
    </dependencyManagement>`,
    );
    withTempPom(pom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "com.fasterxml.jackson.core:jackson-core", targetVersion: "2.21.9", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-core");
      const after = readPom(filePath);
      expect(after).toContain("<jackson-core.version>2.21.9</jackson-core.version>");
    });
  });

  it("pins BOM-managed dependencies that declare no version", () => {
    withTempPom(basePom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "io.quarkus:quarkus-arc", targetVersion: "3.36.3", because: ["GHSA-test"] },
      ]);
      expect(result.constrained).toContain("io.quarkus:quarkus-arc");
      const after = readPom(filePath);
      expect(after).toContain(POM_MARKER_BEGIN);
      expect(versionOf(after, "io.quarkus", "quarkus-arc")).toBe("3.36.3");
    });
  });

  it("rewrites the local property for a GA managed only in dependencyManagement", () => {
    const pom = basePom
      .replace(
        "<jackson-core.version>2.21.2</jackson-core.version>",
        "<jackson-core.version>2.21.2</jackson-core.version>\n        <postgresql.version>42.7.12</postgresql.version>",
      )
      .replace(
        "    </dependencyManagement>",
        `        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>\${postgresql.version}</version>
        </dependency>
    </dependencyManagement>`,
      );
    withTempPom(pom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "org.postgresql:postgresql", targetVersion: "42.7.14", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("org.postgresql:postgresql");
      expect(result.constrained).toHaveLength(0);
      const after = readPom(filePath);
      expect(after).toContain("<postgresql.version>42.7.14</postgresql.version>");
      expect(after).not.toContain(POM_MARKER_BEGIN);
    });
  });

  it("removes a stale pin once the package becomes directly rewritable", () => {
    const pom = basePom.replace(
      "    </dependencyManagement>",
      `${POM_MARKER_BEGIN}
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-core</artifactId>
    <version>2.21.7</version>
  </dependency>
${POM_MARKER_END}
    </dependencyManagement>`,
    );
    withTempPom(pom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "com.fasterxml.jackson.core:jackson-core", targetVersion: "2.21.9", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("com.fasterxml.jackson.core:jackson-core");
      const after = readPom(filePath);
      expect(after).toContain("<jackson-core.version>2.21.9</jackson-core.version>");
      expect(after).not.toContain(POM_MARKER_BEGIN);
    });
  });
});

describe("applyBumps pin placement (pom without dependencyManagement)", () => {
  const noDmPom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>plain-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.mozilla</groupId>
            <artifactId>rhino</artifactId>
            <version>1.7.7.2</version>
        </dependency>
    </dependencies>
</project>
`;

  it("creates a dependencyManagement section for the pin instead of a real dependency", () => {
    withTempPom(noDmPom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "org.example:orphan-lib", targetVersion: "2.0.0", because: ["GHSA-test"] },
      ]);
      expect(result.constrained).toContain("org.example:orphan-lib");
      const after = readPom(filePath);
      const dmRegion = /<dependencyManagement>[\s\S]*?<\/dependencyManagement>/.exec(after)?.[0] ?? "";
      expect(dmRegion).toContain(POM_MARKER_BEGIN);
      expect(versionOf(dmRegion, "org.example", "orphan-lib")).toBe("2.0.0");
      const topLevel = after.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "");
      expect(topLevel).not.toContain("orphan-lib");
    });
  });
});

describe("applyBumps pin placement (pom with dependencyManagement, no existing marker)", () => {
  it("inserts the new pin block inside the dependencyManagement dependencies element", () => {
    withTempPom(basePom, filePath => {
      applyBumps(filePath, [
        { packageName: "org.example:orphan-lib", targetVersion: "2.0.0", because: ["GHSA-test"] },
      ]);
      const after = readPom(filePath);
      const dmStart = after.indexOf("<dependencyManagement>");
      const dmEnd = after.indexOf("</dependencyManagement>");
      const markerIdx = after.indexOf(POM_MARKER_BEGIN);
      expect(markerIdx).toBeGreaterThan(dmStart);
      expect(markerIdx).toBeLessThan(dmEnd);
      const dmRegion = after.slice(dmStart, dmEnd);
      const depsClose = dmRegion.lastIndexOf("</dependencies>");
      expect(dmRegion.slice(depsClose)).not.toContain("<dependency>");
    });
  });
  it("relocates a misplaced marker block into the dependencyManagement dependencies element", () => {
    const pom = basePom.replace(
      "        </dependencies>\n    </dependencyManagement>",
      `        </dependencies>
${POM_MARKER_BEGIN}
  <dependency>
    <groupId>org.example</groupId>
    <artifactId>existing-lib</artifactId>
    <version>1.0.0</version>
  </dependency>
${POM_MARKER_END}
    </dependencyManagement>`,
    );
    withTempPom(pom, filePath => {
      applyBumps(filePath, [
        { packageName: "org.example:orphan-lib", targetVersion: "2.0.0", because: ["GHSA-test"] },
      ]);
      const after = readPom(filePath);
      const dmStart = after.indexOf("<dependencyManagement>");
      const dmEnd = after.indexOf("</dependencyManagement>");
      const markerIdx = after.indexOf(POM_MARKER_BEGIN);
      expect(markerIdx).toBeGreaterThan(dmStart);
      expect(markerIdx).toBeLessThan(dmEnd);
      const dmRegion = after.slice(dmStart, dmEnd);
      const depsClose = dmRegion.lastIndexOf("</dependencies>");
      expect(dmRegion.slice(depsClose)).not.toContain("<dependency>");
      expect(versionOf(after, "org.example", "existing-lib")).toBe("1.0.0");
      expect(versionOf(after, "org.example", "orphan-lib")).toBe("2.0.0");
    });
  });
});

