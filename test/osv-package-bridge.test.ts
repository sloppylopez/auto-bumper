import { describe, expect, it } from "bun:test";
import {
  enrichOsvVulnWithBridgedPackages,
  packagesNeedOrphanBridge,
  resolveBridgedMavenPackages,
} from "../src/lib/osv-package-bridge.ts";
import { extractCveIdsFromHtml } from "../src/lib/osv-orphan-cves.ts";
import { mapOsvVulnToAdvisory } from "../src/lib/osv-export.ts";
import { matchVulnerabilities } from "../src/lib/matcher.ts";

/** Shape of CVE-2026-49844 as published by OSV (no affected.package). */
const CVE_2026_49844_ORPHAN = {
  id: "CVE-2026-49844",
  summary:
    "Apache Log4j API: Improper serialization of non-finite floating-point values in MapMessage.asJson()",
  details:
    "This issue affects Apache Log4j API versions 2.13.1 through 2.25.4 and version 2.26.0.",
  severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N" }],
  affected: [
    {
      ranges: [
        {
          type: "GIT",
          repo: "https://github.com/apache/logging-log4j2",
          events: [
            { introduced: "a8b4a5a0fe05c2985e1d1e0e748bef83c47a0ce4" },
            { fixed: "2e1d9c6284af1da1dec189f4b5b98ac0f32a7645" },
          ],
          database_specific: {
            cpe: [
              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
              "cpe:2.3:a:apache:log4j:2.26.0:*:*:*:*:*:*:*",
            ],
            extracted_events: [
              { introduced: "2.13.1" },
              { fixed: "2.25.5" },
              { introduced: "2.26.0" },
              { last_affected: "2.26.0" },
            ],
          },
        },
      ],
      versions: ["2.26.0", "rel/2.25.4"],
    },
  ],
  references: [{ url: "https://logging.apache.org/security.html#CVE-2026-49844" }],
};
/** Shape of CVE-2026-86321 as published by OSV (no affected.package, GIT range only). */
const CVE_2026_86321_ORPHAN = {
  id: "CVE-2026-86321",
  summary: "jackson-coreutils JsonLoader.fromURL server-side request forgery",
  details: "",
  severity: [{ type: "CVSS_V3_1", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N" }],
  affected: [
    {
      ranges: [
        {
          type: "GIT",
          repo: "https://github.com/java-json-tools/jackson-coreutils",
          events: [
            { introduced: "4575e2b026ed90ffa731a1c7e42be4817c9b1bd7" },
            { last_affected: "4575e2b026ed90ffa731a1c7e42be4817c9b1bd7" },
          ],
          database_specific: {
            extracted_events: [{ introduced: "2.0" }, { last_affected: "2.0" }],
          },
        },
      ],
    },
  ],
  references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2026-86321" }],
};

describe("osv-package-bridge", () => {
  it("resolves apache:log4j CPE to log4j-api when summary says Log4j API", () => {
    const names = resolveBridgedMavenPackages(
      CVE_2026_49844_ORPHAN.affected[0]!,
      CVE_2026_49844_ORPHAN.summary,
      CVE_2026_49844_ORPHAN.details,
    );
    expect(names).toEqual(["org.apache.logging.log4j:log4j-api"]);
  });

  it("enriches package-less OSV record with Maven package", () => {
    const enriched = enrichOsvVulnWithBridgedPackages(CVE_2026_49844_ORPHAN);
    const affected = enriched.affected as Array<{ package?: { name?: string; ecosystem?: string } }>;
    expect(affected).toHaveLength(1);
    expect(affected[0]!.package).toEqual({
      ecosystem: "Maven",
      name: "org.apache.logging.log4j:log4j-api",
    });
  });

  it("mapOsvVulnToAdvisory exposes Maven ecosystem after bridge", () => {
    const adv = mapOsvVulnToAdvisory(CVE_2026_49844_ORPHAN);
    expect(adv.ecosystems.map(e => e.toLowerCase())).toContain("maven");
    expect(adv.affected[0]?.package?.name).toBe("org.apache.logging.log4j:log4j-api");
  });

  it("matcher flags log4j-api@2.24.3 and clears 2.25.5", () => {
    const adv = mapOsvVulnToAdvisory(CVE_2026_49844_ORPHAN);
    const bad = matchVulnerabilities(
      [{ ecosystem: "maven", name: "org.apache.logging.log4j:log4j-api", version: "2.24.3", manifestPath: "build.gradle" }],
      [adv],
    );
    expect(bad.map(f => f.id)).toContain("CVE-2026-49844");
    expect(bad[0]?.fixedVersions).toContain("2.25.5");

    const good = matchVulnerabilities(
      [{ ecosystem: "maven", name: "org.apache.logging.log4j:log4j-api", version: "2.25.5", manifestPath: "build.gradle" }],
      [adv],
    );
    expect(good).toHaveLength(0);
  });

  it("packagesNeedOrphanBridge detects log4j maven coords", () => {
    expect(
      packagesNeedOrphanBridge([
        { ecosystem: "maven", name: "org.apache.logging.log4j:log4j-to-slf4j" },
      ]),
    ).toBe(true);
    expect(
      packagesNeedOrphanBridge([{ ecosystem: "maven", name: "org.springframework:spring-core" }]),
    ).toBe(false);
  });

  it("resolves jackson-coreutils repo signal to its Maven coord", () => {
    const names = resolveBridgedMavenPackages(
      CVE_2026_86321_ORPHAN.affected[0]!,
      CVE_2026_86321_ORPHAN.summary,
      "",
    );
    expect(names).toEqual(["com.github.java-json-tools:jackson-coreutils"]);
  });

  it("matcher flags jackson-coreutils@2.0 with no fixed version and clears 1.12", () => {
    const adv = mapOsvVulnToAdvisory(CVE_2026_86321_ORPHAN);
    expect(adv.ecosystems.map(e => e.toLowerCase())).toContain("maven");

    const bad = matchVulnerabilities(
      [{ ecosystem: "maven", name: "com.github.java-json-tools:jackson-coreutils", version: "2.0", manifestPath: "build.gradle" }],
      [adv],
    );
    expect(bad.map(f => f.id)).toContain("CVE-2026-86321");
    expect(bad[0]?.fixedVersions).toEqual([]);

    const good = matchVulnerabilities(
      [{ ecosystem: "maven", name: "com.github.java-json-tools:jackson-coreutils", version: "1.12", manifestPath: "build.gradle" }],
      [adv],
    );
    expect(good).toHaveLength(0);
  });

  it("packagesNeedOrphanBridge detects jackson-coreutils maven coord", () => {
    expect(
      packagesNeedOrphanBridge([{ ecosystem: "maven", name: "com.github.java-json-tools:jackson-coreutils" }]),
    ).toBe(true);
  });
});

describe("extractCveIdsFromHtml", () => {
  it("collects unique CVE ids", () => {
    const html = "see CVE-2026-49844 and cve-2021-44228 plus CVE-2026-49844 again";
    expect(extractCveIdsFromHtml(html).sort()).toEqual(["CVE-2021-44228", "CVE-2026-49844"]);
  });
});
