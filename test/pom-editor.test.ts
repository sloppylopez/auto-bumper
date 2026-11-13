import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AUTO_DEPENDER_POM_MARKER_BEGIN, AUTO_DEPENDER_POM_MARKER_END, POM_MARKER_BEGIN, POM_MARKER_END } from "../src/lib/brand.ts";
import { applyBumps, removeManagedPin } from "../src/lib/pom-editor.ts";

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

  it("defines a parent property locally so the pin is not ignored", () => {
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
      expect(result.direct).toContain("org.example:parent-managed");
      expect(result.constrained).toHaveLength(0);
      const after = readPom(filePath);
      expect(after).toContain("<parent.managed.version>9.9.9</parent.managed.version>");
      expect(after).not.toContain(POM_MARKER_BEGIN);
    });
  });

  it("writes an explicit version on a direct dependency that a BOM managed", () => {
    const pom = basePom.replace(
      "    </dependencies>\n</project>",
      `        <dependency>
            <groupId>org.example</groupId>
            <artifactId>bom-managed</artifactId>
        </dependency>
    </dependencies>
</project>`,
    );
    withTempPom(pom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "org.example:bom-managed", targetVersion: "2.0.0", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("org.example:bom-managed");
      const after = readPom(filePath);
      expect(versionOf(after, "org.example", "bom-managed")).toBe("2.0.0");
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

  it("writes an explicit version on a BOM-managed direct dependency", () => {
    withTempPom(basePom, filePath => {
      const result = applyBumps(filePath, [
        { packageName: "io.quarkus:quarkus-arc", targetVersion: "3.36.3", because: ["GHSA-test"] },
      ]);
      expect(result.direct).toContain("io.quarkus:quarkus-arc");
      const after = readPom(filePath);
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

describe("applyBumps Maven exclusions", () => {
  const pom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>managed</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`;

  it("adds an exclusion on a direct dependency and does not duplicate it", () => {
    withTempPom(pom, filePath => {
      const first = applyBumps(filePath, [], [{ packageName: "org.bad:lib" }]);
      const once = readPom(filePath);
      expect(first.excluded).toEqual(["org.bad:lib"]);
      expect(once).toContain("<groupId>org.bad</groupId>");
      expect(once).toContain("<artifactId>lib</artifactId>");
      const managed = once.slice(once.indexOf("<dependencyManagement>"));
      expect(managed).not.toContain("org.bad");
      applyBumps(filePath, [], [{ packageName: "org.bad:lib" }]);
      const twice = readPom(filePath);
      expect(twice.match(/<exclusion>/g)?.length).toBe(1);
    });
  });

  it("keeps an exclusion on the real block when a comment contains a closing tag", () => {
    const commented = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <!-- </dependency> -->
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
`;
    withTempPom(commented, filePath => {
      const result = applyBumps(filePath, [], [{ packageName: "org.bad:lib" }]);
      const xml = readPom(filePath);
      expect(result.excluded).toEqual(["org.bad:lib"]);
      expect(xml).toContain("<version>1.0.0</version>");
      const dep = xml.slice(xml.indexOf("<dependencies>"), xml.indexOf("</dependencies>"));
      expect(dep.match(/<exclusion>/g)?.length).toBe(1);
      expect(dep).toContain("<artifactId>lib</artifactId>");
    });
  });

  it("warns when there is no direct dependency to attach", () => {
    const bare = `<?xml version="1.0" encoding="UTF-8"?>\n<project>\n  <dependencyManagement>\n    <dependencies>\n      <dependency>\n        <groupId>com.example</groupId>\n        <artifactId>managed</artifactId>\n        <version>1.0.0</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>\n</project>\n`;
    withTempPom(bare, filePath => {
      const result = applyBumps(filePath, [], [{ packageName: "org.bad:lib" }]);
      expect(result.excluded).toEqual([]);
      expect(result.warnings.some(w => w.includes("no direct dependency"))).toBe(true);
    });
  });

  it("attaches a scoped exclusion only to its resolved sources", () => {
    const scopedPom = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>app</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>client</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>
`;
    const blockOf = (xml: string, artifactId: string) => {
      const i = xml.indexOf(`<artifactId>${artifactId}</artifactId>`);
      const start = xml.lastIndexOf("<dependency>", i);
      return xml.slice(start, xml.indexOf("</dependency>", i));
    };
    withTempPom(scopedPom, filePath => {
      const result = applyBumps(filePath, [], [{ packageName: "org.bad:lib", attachTo: ["com.example:client"] }]);
      expect(result.excluded).toEqual(["org.bad:lib"]);
      const xml = readPom(filePath);
      expect(blockOf(xml, "client")).toContain("<groupId>org.bad</groupId>");
      expect(blockOf(xml, "app")).not.toContain("org.bad");
    });
  });

  it("warns and changes nothing when a scoped source is not a direct dependency", () => {
    withTempPom(pom, filePath => {
      const before = readPom(filePath);
      const result = applyBumps(filePath, [], [{ packageName: "org.bad:lib", attachTo: ["com.example:missing"] }]);
      expect(result.excluded).toEqual([]);
      expect(result.warnings.some(w => w.includes("none of its resolved sources"))).toBe(true);
      expect(readPom(filePath)).toBe(before);
    });
  });
});

describe("managed block comment preservation (Maven)", () => {
  function pomWithPins(pins: Array<{ pkg: string; version: string; comment?: string }>): string {
    const lines = [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<project>",
      "    <modelVersion>4.0.0</modelVersion>",
      "    <groupId>com.example</groupId>",
      "    <artifactId>email-app</artifactId>",
      "    <version>1.0.0</version>",
      "    <dependencyManagement>",
      "        <dependencies>",
      POM_MARKER_BEGIN,
    ];
    for (const { pkg, version, comment } of pins) {
      const [group, artifact] = pkg.split(":");
      if (comment) lines.push(`  <!-- ${comment} -->`);
      lines.push(
        "  <dependency>",
        `    <groupId>${group}</groupId>`,
        `    <artifactId>${artifact}</artifactId>`,
        `    <version>${version}</version>`,
        "  </dependency>",
      );
    }
    lines.push(POM_MARKER_END, "        </dependencies>", "    </dependencyManagement>", "</project>");
    return lines.join("\n");
  }

  it("keeps a human comment above a pin when the managed block is re-rendered", () => {
    withTempPom(pomWithPins([
      { pkg: "com.networknt:json-schema-validator", version: "2.2.13", comment: "Pinned below 2.3.x: json-patch 1.13 throws NoSuchMethodError under coreutils 1.12." },
    ]), filePath => {
      applyBumps(filePath, [{
        packageName: "com.example:other-lib",
        targetVersion: "1.0.1",
        because: ["CVE-TEST"],
      }]);
      const after = readPom(filePath);
      expect(after).toContain("NoSuchMethodError under coreutils 1.12.");
      // The comment must still sit directly above its pin's dependency element.
      const lines = after.split("\n");
      const pinIdx = lines.findIndex(l => l.includes("<artifactId>json-schema-validator</artifactId>"));
      expect(lines.slice(pinIdx - 5, pinIdx).join(" ")).toContain("NoSuchMethodError");
    });
  });

  it("drops the comment of a removed pin but keeps the others", () => {
    withTempPom(pomWithPins([
      { pkg: "com.example:keep-old", version: "1.0.0", comment: "documents why this stays pinned" },
      { pkg: "com.example:drop-me", version: "1.0.0", comment: "this pin is going away" },
    ]), filePath => {
      expect(removeManagedPin(filePath, "com.example:drop-me")).toBe(true);
      const after = readPom(filePath);
      expect(after).toContain("documents why this stays pinned");
      expect(after).not.toContain("this pin is going away");
      expect(versionOf(after, "com.example", "keep-old")).toBe("1.0.0");
    });
  });
});

describe("legacy managed-block brands", () => {
  function dualPom(pinsLegacy: Array<{ pkg: string; version: string }>, pinsCurrent: Array<{ pkg: string; version: string }>): string {
    const dep = (pkg: string, version: string) => {
      const [groupId, artifactId] = pkg.split(":");
      return [
        "            <dependency>",
        `                <groupId>${groupId}</groupId>`,
        `                <artifactId>${artifactId}</artifactId>`,
        `                <version>${version}</version>`,
        "            </dependency>",
      ].join("\n");
    };
    return [
      '<?xml version="1.0" encoding="UTF-8"?>',
      "<project>",
      "    <modelVersion>4.0.0</modelVersion>",
      "    <groupId>com.example</groupId>",
      "    <artifactId>app</artifactId>",
      "    <version>0.1</version>",
      "    <dependencyManagement>",
      "        <dependencies>",
      AUTO_DEPENDER_POM_MARKER_BEGIN,
      ...pinsLegacy.map(p => dep(p.pkg, p.version)),
      AUTO_DEPENDER_POM_MARKER_END,
      POM_MARKER_BEGIN,
      ...pinsCurrent.map(p => dep(p.pkg, p.version)),
      POM_MARKER_END,
      "        </dependencies>",
      "    </dependencyManagement>",
      "</project>",
    ].join("\n");
  }

  it("consolidates a pre-existing auto-depender pin block into the canonical one", () => {
    withTempPom(dualPom(
      [{ pkg: "ch.qos.logback:logback-classic", version: "1.6.5" }],
      [{ pkg: "org.glassfish.jaxb:jaxb-core", version: "3.0.2" }],
    ), filePath => {
      applyBumps(filePath, [{
        packageName: "org.objenesis:objenesis",
        targetVersion: "3.6",
        because: ["CVE-2026-116486"],
      }]);
      const after = readPom(filePath);
      expect(after.split(POM_MARKER_BEGIN).length - 1).toBe(1);
      expect(after).not.toContain(AUTO_DEPENDER_POM_MARKER_BEGIN);
      expect(versionOf(after, "ch.qos.logback", "logback-classic")).toBe("1.6.5");
      expect(versionOf(after, "org.glassfish.jaxb", "jaxb-core")).toBe("3.0.2");
      expect(versionOf(after, "org.objenesis", "objenesis")).toBe("3.6");
    });
  });

  it("keeps the canonical block's version when both pom blocks pin the same package", () => {
    withTempPom(dualPom(
      [{ pkg: "com.example:lib", version: "1.0.0" }],
      [{ pkg: "com.example:lib", version: "1.2.0" }],
    ), filePath => {
      applyBumps(filePath, [{
        packageName: "com.other:tool",
        targetVersion: "2.0.0",
        because: ["CVE-X"],
      }]);
      const after = readPom(filePath);
      expect(after.split(POM_MARKER_BEGIN).length - 1).toBe(1);
      expect(versionOf(after, "com.example", "lib")).toBe("1.2.0");
      expect(after).not.toContain("<version>1.0.0</version>");
    });
  });

  it("consolidates duplicate canonical blocks when removing a legacy pin", () => {
    withTempPom(dualPom(
      [
        { pkg: "com.example:remove-me", version: "1.0.0" },
        { pkg: "com.example:legacy-keep", version: "2.0.0" },
      ],
      [{ pkg: "com.example:current-keep", version: "3.0.0" }],
    ), filePath => {
      expect(removeManagedPin(filePath, "com.example:remove-me")).toBe(true);
      const after = readPom(filePath);
      expect(after.split(POM_MARKER_BEGIN).length - 1).toBe(1);
      expect(after).not.toContain(AUTO_DEPENDER_POM_MARKER_BEGIN);
      expect(versionOf(after, "com.example", "legacy-keep")).toBe("2.0.0");
      expect(versionOf(after, "com.example", "current-keep")).toBe("3.0.0");
    });
  });
});
