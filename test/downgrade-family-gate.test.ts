import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { downgradeFamilyGate } from "../cli/fix.ts";
import type { FixCandidate } from "../src/lib/fixer.ts";
import type { AdvisoryEntry } from "../src/lib/types.ts";

const JAXB_CORE = "org.glassfish.jaxb:jaxb-core";
const JAXB_RUNTIME = "org.glassfish.jaxb:jaxb-runtime";

function withTempManifest(content: string, run: (filePath: string) => Promise<void>): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-gate-"));
  const filePath = path.join(dir, "build.gradle");
  fs.writeFileSync(filePath, content, "utf-8");
  return run(filePath).finally(() => fs.rmSync(dir, { recursive: true, force: true }));
}

function candidate(): FixCandidate {
  return {
    packageName: JAXB_CORE,
    installedVersion: "4.0.9",
    targetVersion: "3.0.2",
    isMajor: true,
    isDowngrade: true,
    ecosystem: "maven",
    findingIds: ["CVE-2026-92877"],
    severity: "HIGH",
  };
}

const TARGET = "3.0.2";

const classpath = [
  { packageName: JAXB_CORE, installedVersion: "4.0.9", ecosystem: "maven" },
  { packageName: JAXB_RUNTIME, installedVersion: "4.0.9", ecosystem: "maven" },
];

describe("downgradeFamilyGate", () => {
  it("refuses when the primary is user-pinned on another line and the pinned version is not affected", async () => {
    // No advisories: the user's explicit force at 4.0.9 pins a clean version — respect it.
    const manifest = [
      `def jaxb_version = "4.0.9"`,
      `configurations.all {`,
      `    resolutionStrategy { force "org.glassfish.jaxb:jaxb-core:\${jaxb_version}" }`,
      `}`,
      ``,
    ].join("\n");

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async () => ["3.0.2", "4.0.9"],
      );
      expect("refuse" in outcome).toBe(true);
      if ("refuse" in outcome) {
        expect(outcome.refuse).toContain(JAXB_CORE);
        expect(outcome.refuse).toContain("pins");
        expect(outcome.refuse).toContain("4.0.9");
      }
    });
  });

  it("refuses when a family sibling is user-pinned on another line", async () => {
    const manifest = [
      `def rt_version = "4.0.9"`,
      `configurations.all {`,
      `    resolutionStrategy { force "org.glassfish.jaxb:jaxb-runtime:\${rt_version}" }`,
      `}`,
      ``,
    ].join("\n");

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async () => ["3.0.2", "4.0.9"],
      );
      expect("refuse" in outcome).toBe(true);
      if ("refuse" in outcome) {
        expect(outcome.refuse).toContain(JAXB_RUNTIME);
        expect(outcome.refuse).toContain("4.0.9");
      }
    });
  });

  it("pulls siblings along to the target line when nobody is user-pinned", async () => {
    const manifest = `dependencies {\n    implementation "com.example:app"\n}\n`;

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async pkg => (pkg === JAXB_RUNTIME ? ["3.0.5", "4.0.9"] : ["3.0.2", "4.0.9"]),
      );
      expect("pullAlong" in outcome).toBe(true);
      if ("pullAlong" in outcome) {
        expect(outcome.pullAlong).toHaveLength(1);
        const pulled = outcome.pullAlong[0];
        expect(pulled.packageName).toBe(JAXB_RUNTIME);
        expect(pulled.installedVersion).toBe("4.0.9");
        // Exact 3.0.2 is not published for the sibling → highest safe release on the line.
        expect(pulled.targetVersion).toBe("3.0.5");
        expect(pulled.isDowngrade).toBe(true);
      }
    });
  });

  it("prefers the primary's exact version when published for a sibling", async () => {
    const manifest = `dependencies {\n    implementation "com.example:app"\n}\n`;

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async () => ["3.0.2", "3.0.5", "4.0.9"],
      );
      expect("pullAlong" in outcome).toBe(true);
      if ("pullAlong" in outcome) {
        expect(outcome.pullAlong[0].targetVersion).toBe("3.0.2");
      }
    });
  });

  it("refuses when the sibling's published releases cannot be verified", async () => {
    const manifest = `dependencies {\n    implementation "com.example:app"\n}\n`;

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async pkg => (pkg === JAXB_RUNTIME ? null : ["3.0.2", "4.0.9"]),
      );
      expect("refuse" in outcome).toBe(true);
      if ("refuse" in outcome) {
        expect(outcome.refuse).toContain(JAXB_RUNTIME);
        expect(outcome.refuse).toContain("cannot verify");
      }
    });
  });

  it("refuses when no safe release exists on the target line for a sibling", async () => {
    const manifest = `dependencies {\n    implementation "com.example:app"\n}\n`;

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [],
        async pkg => (pkg === JAXB_RUNTIME ? ["4.0.9"] : ["3.0.2", "4.0.9"]),
      );
      expect("refuse" in outcome).toBe(true);
      if ("refuse" in outcome) {
        expect(outcome.refuse).toContain(JAXB_RUNTIME);
        expect(outcome.refuse).toContain("no safe 3.x release");
      }
    });
  });

  it("is a no-op for packages outside the family table", async () => {
    const manifest = `dependencies {\n    implementation "com.example:app"\n}\n`;

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "no-such-family", candidate(), TARGET, classpath, filePath, [],
        async () => ["3.0.2", "4.0.9"],
      );
      expect(outcome).toEqual({ pullAlong: [] });
    });
  });

  it("moves only the candidate (escape pin) when the project's own force pins an affected version", async () => {
    // CVE-2026-92877 shape: introduced, no forward fix. The user's own force at 4.0.9 is itself
    // affected, and a managed force written after it wins (last-wins in Gradle) — so the pin does
    // not make the split permanent. Only the candidate moves; siblings stay on their line.
    const advisory: AdvisoryEntry = {
      id: "SNYK-JAVA-ORGGLASSFISHJAXB-1234567",
      aliases: ["CVE-2026-92877"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: JAXB_CORE, ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.0.0-M4" }] }],
      }],
    };
    const manifest = [
      `def jaxb_version = "4.0.9"`,
      `configurations.all {`,
      `    resolutionStrategy { force "org.glassfish.jaxb:jaxb-core:\${jaxb_version}" }`,
      `}`,
      ``,
    ].join("\n");

    await withTempManifest(manifest, async filePath => {
      const outcome = await downgradeFamilyGate(
        "jaxb", candidate(), TARGET, classpath, filePath, [advisory],
        async () => ["3.0.2", "4.0.9"],
      );
      expect("refuse" in outcome).toBe(false);
      if (!("refuse" in outcome)) {
        expect(outcome.pullAlong).toEqual([]);
        expect(outcome.note).toContain("escape pin");
        expect(outcome.note).toContain("4.0.9");
      }
    });
  });
});
