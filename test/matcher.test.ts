import {
  compareMavenVersion,
  matchesMavenRange,
  comparePEP440,
  matchesPEP440Range,
  matchVulnerabilities,
  normalizePyPIName,
  dropShadowedDuplicates,
} from "../src/lib/matcher.ts";
import { buildFixPlan } from "../src/lib/fixer.ts";

// ─── Maven Version Comparison ──────────────────────────────

describe("compareMavenVersion", () => {
  it("returns negative when first < second", () => {
    expect(compareMavenVersion("1.0", "2.0")).toBeLessThan(0);
  });

  it("returns zero for equal versions", () => {
    expect(compareMavenVersion("1.0", "1.0")).toBe(0);
    expect(compareMavenVersion("1.2.3", "1.2.3")).toBe(0);
  });

  it("returns positive when first > second", () => {
    expect(compareMavenVersion("2.0", "1.0")).toBeGreaterThan(0);
  });

  it("handles multi-part versions", () => {
    expect(compareMavenVersion("1.2.3", "1.2.4")).toBeLessThan(0);
    expect(compareMavenVersion("1.3.0", "1.2.9")).toBeGreaterThan(0);
  });

  it("handles SNAPSHOT qualifier", () => {
    expect(compareMavenVersion("1.0-SNAPSHOT", "1.0")).toBeLessThan(0);
  });
});

// ─── Maven Range Matching ──────────────────────────────────

describe("matchesMavenRange", () => {
  it("matches version within inclusive-exclusive range [1.0,2.0)", () => {
    expect(matchesMavenRange("1.5", "[1.0,2.0)")).toBe(true);
  });

  it("matches version at lower bound inclusively", () => {
    expect(matchesMavenRange("1.0", "[1.0,2.0)")).toBe(true);
  });

  it("matches inclusive-inclusive range [1.0,2.0]", () => {
    expect(matchesMavenRange("2.0", "[1.0,2.0]")).toBe(true);
  });

  it("matches exclusive-lower bound (1.0,2.0)", () => {
    expect(matchesMavenRange("1.5", "(1.0,2.0)")).toBe(true);
  });
});

// ─── PEP 440 Version Comparison ─────────────────────────────

describe("comparePEP440", () => {
  it("returns negative when first < second", () => {
    expect(comparePEP440("1.0", "2.0")).toBeLessThan(0);
  });

  it("returns zero for equal versions", () => {
    expect(comparePEP440("1.0", "1.0")).toBe(0);
    expect(comparePEP440("1.2.3", "1.2.3")).toBe(0);
  });

  it("returns positive when first > second", () => {
    expect(comparePEP440("2.0", "1.0")).toBeGreaterThan(0);
  });

  it("handles pre-release versions", () => {
    // Alpha < beta ordering within same version
    expect(comparePEP440("1.0a", "1.0b")).toBeLessThan(0);
    // Beta < rc ordering
    expect(comparePEP440("1.0b", "1.0rc")).toBeLessThan(0);
  });

  it("handles post versions", () => {
    expect(comparePEP440("1.0.post1", "1.0")).toBeGreaterThan(0);
  });
});

// ─── PEP 440 Range Matching ────────────────────────────────

describe("matchesPEP440Range", () => {
  it("matches version in >=X,<Y range", () => {
    expect(matchesPEP440Range("1.5.0", ">=1.0,<2.0")).toBe(true);
  });

  it("does not match version below lower bound", () => {
    expect(matchesPEP440Range("0.9", ">=1.0,<2.0")).toBe(false);
  });

  it("does not match version at upper bound", () => {
    expect(matchesPEP440Range("2.0", ">=1.0,<2.0")).toBe(false);
  });

  it("handles compatible release ~= operator", () => {
    // PEP 440: ~=1.4 is >=1.4,==1.* ; ~=1.4.5 is >=1.4.5,==1.4.*
    expect(matchesPEP440Range("1.4.2", "~=1.4")).toBe(true);
    expect(matchesPEP440Range("1.5", "~=1.4")).toBe(true);
    expect(matchesPEP440Range("2.0", "~=1.4")).toBe(false);
    expect(matchesPEP440Range("1.4.6", "~=1.4.5")).toBe(true);
    expect(matchesPEP440Range("1.5.0", "~=1.4.5")).toBe(false);
  });

  it("handles OR groups with ||", () => {
    expect(matchesPEP440Range("3.2", ">=1.0,<2.0||>=3.0,<4.0")).toBe(true);
  });

  it("handles wildcard ==3.* pattern", () => {
    expect(matchesPEP440Range("3.2.1", "==3.*")).toBe(true);
    expect(matchesPEP440Range("4.0", "==3.*")).toBe(false);
    expect(matchesPEP440Range("1.4.2", "==1.4.*")).toBe(true);
    expect(matchesPEP440Range("1.5.0", "==1.4.*")).toBe(false);
  });
});

// ─── PyPI Name Normalization ────────────────────────────────

describe("normalizePyPIName", () => {
  it("collapses underscores, hyphens, spaces to single dash", () => {
    expect(normalizePyPIName("some_package-name")).toBe("some-package-name");
    expect(normalizePyPIName("Some Package_Name")).toBe("some-package-name");
  });

  it("lowercases input", () => {
    expect(normalizePyPIName("React")).toBe("react");
  });
});

// ─── Match Vulnerabilities ──────────────────────────────────

describe("matchVulnerabilities", () => {
  it("returns empty findings for no matching entries", () => {
    const packages = [{ ecosystem: "npm", name: "lodash", version: "4.5.0", manifestPath: "package-lock.json" }];
    const osvData = [];
    const results = matchVulnerabilities(packages, osvData);
    expect(results).toEqual([]);
  });

  it("produces findings when package matches OSV entry", () => {
    const packages = [{ ecosystem: "npm", name: "chalk", version: "4.0.0", manifestPath: "package-lock.json" }];
    const osvData = [{
      id: "GHSA-test-chalk",
      aliases: ["CVE-2024-1234"],
      ecosystems: ["npm"],
      affected: [{
        package: { name: "chalk" },
        versions: ["4.0.0"],
        ranges: [],
      }],
      summary: "Test vulnerability in chalk",
    }];
    const results = matchVulnerabilities(packages, osvData);
    expect(results.length).toBeGreaterThanOrEqual(1);
    if (results.length > 0) {
      expect(results[0].packageName).toBe("chalk");
      expect(results[0].installedVersion).toBe("4.0.0");
    }
  });

  it("does not flag version above fixed ECOSYSTEM range", () => {
    const packages = [{
      ecosystem: "maven",
      name: "org.apache.tomcat.embed:tomcat-embed-core",
      version: "10.1.56",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-tomcat-test",
      aliases: ["CVE-2024-34750"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "10.1.0-M1" }, { fixed: "10.1.25" }],
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(0);
  });

  it("does not flag version outside last_affected ECOSYSTEM range", () => {
    const packages = [{
      ecosystem: "maven",
      name: "org.apache.tomcat.embed:tomcat-embed-core",
      version: "10.1.56",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-tomcat-85",
      aliases: ["CVE-2024-34750"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "8.5.0" }, { last_affected: "8.5.100" }],
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(0);
  });

  it("flags version inside last_affected ECOSYSTEM range", () => {
    const packages = [{
      ecosystem: "maven",
      name: "org.apache.tomcat.embed:tomcat-embed-core",
      version: "8.5.99",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-tomcat-85-hit",
      aliases: ["CVE-TEST-85"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "8.5.0" }, { last_affected: "8.5.100" }],
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(1);
  });

  it("does not flag patched jackson 2.21.5", () => {
    const packages = [{
      ecosystem: "maven",
      name: "com.fasterxml.jackson.core:jackson-databind",
      version: "2.21.5",
      manifestPath: "build.gradle",
    }];
    const osvData = [{
      id: "GHSA-jackson-patched",
      aliases: ["CVE-2026-54515"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "com.fasterxml.jackson.core:jackson-databind", ecosystem: "Maven" },
        versions: ["2.21.4"],
        ranges: [{
          type: "GIT",
          events: [],
          database_specific: {
            extracted_events: [
              { introduced: "2.19.0" },
              { fixed: "2.21.5" },
              { introduced: "3.0.0" },
              { fixed: "3.1.4" },
            ],
          },
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(0);
  });

  it("collects fixed versions from database_specific extracted_events", () => {
    const packages = [{
      ecosystem: "maven",
      name: "com.fasterxml.jackson.core:jackson-databind",
      version: "2.21.4",
      manifestPath: "build.gradle",
    }];
    const osvData = [{
      id: "GHSA-jackson-test",
      aliases: ["CVE-2026-54515"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "com.fasterxml.jackson.core:jackson-databind", ecosystem: "Maven" },
        versions: ["2.21.4"],
        ranges: [{
          type: "GIT",
          events: [],
          database_specific: {
            extracted_events: [
              { introduced: "2.19.0" },
              { fixed: "2.21.5" },
              { introduced: "3.0.0" },
              { fixed: "3.1.4" },
            ],
          },
        }],
      }],
    }];
    const findings = matchVulnerabilities(packages, osvData);
    expect(findings).toHaveLength(1);
    expect(findings[0].fixedVersions).toContain("2.21.5");
    expect(findings[0].fixedVersions).toContain("3.1.4");
  });

  it("collects fixed versions only from matching affected package", () => {
    const packages = [{
      ecosystem: "maven",
      name: "com.foo:bar",
      version: "1.0.0",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-multi-pkg",
      aliases: [],
      ecosystems: ["Maven"],
      affected: [
        {
          package: { name: "com.foo:bar", ecosystem: "Maven" },
          ranges: [{
            type: "ECOSYSTEM",
            events: [{ introduced: "0" }, { fixed: "1.0.1" }],
          }],
        },
        {
          package: { name: "com.other:baz", ecosystem: "Maven" },
          ranges: [{
            type: "ECOSYSTEM",
            events: [{ introduced: "0" }, { fixed: "2.0.0" }],
          }],
        },
      ],
    }];
    const findings = matchVulnerabilities(packages, osvData);
    expect(findings).toHaveLength(1);
    expect(findings[0].fixedVersions).toContain("1.0.1");
    expect(findings[0].fixedVersions).not.toContain("2.0.0");
  });

  it("sorts findings by severity descending", () => {
    const packages = [
      { ecosystem: "npm", name: "pkg-a", version: "1.0.0", manifestPath: "lock.json" },
      { ecosystem: "npm", name: "pkg-b", version: "1.0.0", manifestPath: "lock.json" },
    ];
    const osvData = [
      {
        id: "GHSA-low",
        aliases: [],
        ecosystems: ["npm"],
        affected: [{ package: { name: "pkg-a" }, versions: ["1.0.0"], ranges: [] }],
        summary: "Low vuln",
        severity: [{ type: "CVSS_V3_1", score: "3.8" }],
      },
      {
        id: "GHSA-critical",
        aliases: [],
        ecosystems: ["npm"],
        affected: [{ package: { name: "pkg-b" }, versions: ["1.0.0"], ranges: [] }],
        summary: "Critical vuln",
        severity: [{ type: "CVSS_V3_1", score: "9.5" }],
      },
    ];
    const results = matchVulnerabilities(packages, osvData);
    if (results.length >= 2) {
      expect(results[0].severity).toBe("CRITICAL");
      expect(results[1].severity).toBe("LOW");
    }
  });

  it("flags version equal to 'latest' event boundary (inclusive)", () => {
    const packages = [{
      ecosystem: "maven",
      name: "org.apache.tomcat.embed:tomcat-embed-core",
      version: "8.5.100",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-latest-boundary",
      aliases: [],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "8.5.0" }, { latest: "8.5.100" }],
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(1);
  });

  it("flags version equal to 'deprecated' event boundary (inclusive)", () => {
    const packages = [{
      ecosystem: "maven",
      name: "org.apache.tomcat.embed:tomcat-embed-core",
      version: "3.0",
      manifestPath: "pom.xml",
    }];
    const osvData = [{
      id: "GHSA-deprecated-boundary",
      aliases: [],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.apache.tomcat.embed:tomcat-embed-core", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "1.0" }, { deprecated: "3.0" }],
        }],
      }],
    }];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(1);
  });

  it("keeps separate findings for distinct advisories without shared aliases", () => {
    const packages = [{ ecosystem: "npm", name: "chalk", version: "4.0.0", manifestPath: "package-lock.json" }];
    const osvData = [
      { id: "GHSA-distinct-one", aliases: [], ecosystems: ["npm"], affected: [{ package: { name: "chalk" }, versions: ["4.0.0"], ranges: [] }] },
      { id: "GHSA-distinct-two", aliases: [], ecosystems: ["npm"], affected: [{ package: { name: "chalk" }, versions: ["4.0.0"], ranges: [] }] },
    ];
    expect(matchVulnerabilities(packages, osvData)).toHaveLength(2);
  });

  it("merges findings that cross-reference each other via aliases", () => {
    const packages = [{ ecosystem: "npm", name: "chalk", version: "4.0.0", manifestPath: "package-lock.json" }];
    const osvData = [
      { id: "CVE-2024-9999", aliases: ["GHSA-cross-ref"], ecosystems: ["npm"], affected: [{ package: { name: "chalk" }, versions: ["4.0.0"], ranges: [] }] },
      { id: "GHSA-cross-ref", aliases: ["CVE-2024-9999"], ecosystems: ["npm"], affected: [{ package: { name: "chalk" }, versions: ["4.0.0"], ranges: [] }] },
    ];
    const results = matchVulnerabilities(packages, osvData);
    expect(results).toHaveLength(1);
  });
});

// ─── Parallel Release Lines (Maven backports) ──────────────

describe("parallel release lines", () => {
  // Modeled on GHSA-j58c-g352-8h4p (netty-codec-haproxy): mainline and 4.1.x
  // backport line as two affected blocks whose windows overlap numerically.
  const nettyEntry = {
    id: "GHSA-j58c-g352-8h4p",
    aliases: ["CVE-2026-93564"],
    ecosystems: ["Maven"],
    affected: [
      {
        package: { name: "io.netty:netty-codec-haproxy", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "0" }, { last_affected: "4.2.17.Final" }, { fixed: "4.2.18.Final" }],
        }],
      },
      {
        package: { name: "io.netty:netty-codec-haproxy", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "0" }, { last_affected: "4.1.137.Final" }, { fixed: "4.1.138.Final" }],
        }],
      },
    ],
  };
  const pkg = (version: string) => [{ ecosystem: "maven", name: "io.netty:netty-codec-haproxy", version, manifestPath: "pom.xml" }];

  it("does not flag the backport-line fixed version inside the mainline window", () => {
    expect(matchVulnerabilities(pkg("4.1.138.Final"), [nettyEntry])).toHaveLength(0);
  });

  it("still flags a later backport-line version only when below its fix", () => {
    expect(matchVulnerabilities(pkg("4.1.100.Final"), [nettyEntry])).toHaveLength(1);
  });

  it("still flags mainline versions inside the mainline window", () => {
    const findings = matchVulnerabilities(pkg("4.2.5.Final"), [nettyEntry]);
    expect(findings).toHaveLength(1);
    expect(findings[0].fixedVersions).toContain("4.2.18.Final");
  });

  it("does not exclude a version re-introduced above an earlier fix on the same line", () => {
    const regressionEntry = {
      id: "GHSA-regression-line",
      aliases: ["CVE-TEST-REG"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.example:reg-lib", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [
            { introduced: "0" }, { fixed: "3.2.1" },
            { introduced: "3.2.5" }, { fixed: "3.4.0" },
          ],
        }],
      }],
    };
    const packages = [{ ecosystem: "maven", name: "org.example:reg-lib", version: "3.2.7", manifestPath: "pom.xml" }];
    expect(matchVulnerabilities(packages, [regressionEntry])).toHaveLength(1);
  });

  it("never excludes an explicitly listed exact version", () => {
    const explicitEntry = {
      id: "GHSA-explicit-line",
      aliases: ["CVE-TEST-EXPLICIT"],
      ecosystems: ["Maven"],
      affected: [{
        package: { name: "org.example:explicit-lib", ecosystem: "Maven" },
        versions: ["1.0"],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }],
      }],
    };
    const packages = [{ ecosystem: "maven", name: "org.example:explicit-lib", version: "1.0", manifestPath: "pom.xml" }];
    expect(matchVulnerabilities(packages, [explicitEntry])).toHaveLength(1);
  });
});

// ─── Duplicate Advisory Mirrors ─────────────────────────────

describe("duplicate advisory mirrors", () => {
  // Modeled on the real jackson-core trio in the OSV Maven dump:
  // primary GHSA-r7wm-3cxj-wff9 (fixed 3.1.4 for tools.jackson) and its
  // GitHub "Duplicate Advisory" mirror GHSA-642r-3gj9-2pj5 which lost the
  // fixed version and claims an unbounded range from 3.0.0.
  const primary = {
    id: "GHSA-r7wm-3cxj-wff9",
    aliases: ["CVE-2026-68494"],
    ecosystems: ["Maven"],
    summary: "jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)",
    affected: [
      {
        package: { name: "com.fasterxml.jackson.core:jackson-core", ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.18.8" }] }],
      },
      {
        package: { name: "tools.jackson.core:jackson-core", ecosystem: "Maven" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }, { fixed: "3.1.4" }] }],
      },
    ],
  };
  const duplicate = {
    id: "GHSA-642r-3gj9-2pj5",
    aliases: [],
    ecosystems: ["Maven"],
    summary: "Duplicate Advisory: jackson-core: Async parser maxNumberLength bypass via chunked digit accumulation (incomplete fix for GHSA-72hv-8253-57qq)",
    affected: [
      {
        package: { name: "tools.jackson.core:jackson-core", ecosystem: "Maven" },
        versions: ["3.0.0", "3.1.4", "3.1.7", "3.2.3"],
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.0.0" }] }],
      },
    ],
  };

  it("does not flag a patched version when the duplicate mirror is shadowed by the primary", () => {
    const packages = [{ ecosystem: "maven", name: "tools.jackson.core:jackson-core", version: "3.1.7", manifestPath: "pom.xml" }];
    expect(matchVulnerabilities(packages, [primary, duplicate])).toHaveLength(0);
  });

  it("still flags genuinely vulnerable versions via the primary record", () => {
    const packages = [{ ecosystem: "maven", name: "tools.jackson.core:jackson-core", version: "3.1.3", manifestPath: "pom.xml" }];
    const findings = matchVulnerabilities(packages, [primary, duplicate]);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("GHSA-r7wm-3cxj-wff9");
    expect(findings[0].fixedVersions).toContain("3.1.4");
  });

  it("keeps a duplicate mirror when no non-duplicate record bounds the package", () => {
    const packages = [{ ecosystem: "maven", name: "tools.jackson.core:jackson-core", version: "3.1.7", manifestPath: "pom.xml" }];
    expect(matchVulnerabilities(packages, [duplicate])).toHaveLength(1);
  });

  it("keeps a duplicate mirror when the primary bounds only other packages", () => {
    const primaryOtherPkg = { ...primary, affected: [primary.affected[0]] };
    const packages = [{ ecosystem: "maven", name: "tools.jackson.core:jackson-core", version: "3.1.7", manifestPath: "pom.xml" }];
    expect(matchVulnerabilities(packages, [primaryOtherPkg, duplicate])).toHaveLength(1);
  });

  it("dropShadowedDuplicates removes only fully shadowed mirrors", () => {
    const out = dropShadowedDuplicates([primary, duplicate]);
    expect(out.map(e => e.id)).toEqual(["GHSA-r7wm-3cxj-wff9"]);
  });

  it("keeps a mirror with partially shadowed affected blocks", () => {
    const partialMirror = {
      ...duplicate,
      id: "GHSA-partial-mirror",
      affected: [
        duplicate.affected[0],
        {
          package: { name: "org.example:other-lib", ecosystem: "Maven" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }] }],
        },
      ],
    };
    const out = dropShadowedDuplicates([primary, partialMirror]);
    expect(out.map(e => e.id)).toEqual(["GHSA-r7wm-3cxj-wff9", "GHSA-partial-mirror"]);
  });
});

describe("inclusive Maven range is not a fix", () => {
  const pkg = (version: string) => [{
    ecosystem: "maven",
    name: "org.example:lib",
    version,
    manifestPath: "pom.xml",
  }];
  const inclusive = {
    id: "CVE-INCLUSIVE",
    aliases: [],
    ecosystems: ["Maven"],
    summary: "upper bound is still affected",
    severity: [{ type: "CVSS_V3_1", score: "7.5" }],
    affected: [{
      package: { name: "org.example:lib", ecosystem: "Maven" },
      ranges: [{
        type: "ECOSYSTEM",
        events: [{ introduced: "1.0" }, { last_affected: "1.9" }],
        representations: [{ range: "[1.0,1.9]" }],
      }],
    }],
  };

  it("does not treat 1.9 as fixed and does not plan a bump to it", () => {
    const findings = matchVulnerabilities(pkg("1.5"), [inclusive]);
    expect(findings).toHaveLength(1);
    expect(findings[0].fixedVersions).not.toContain("1.9");
    expect(matchVulnerabilities(pkg("1.9"), [inclusive])).toHaveLength(1);
    const plan = buildFixPlan(findings, [inclusive]);
    expect(plan.fixable.map(c => c.targetVersion)).not.toContain("1.9");
  });

  it("still treats an exclusive upper bound as the fix", () => {
    const exclusive = {
      ...inclusive,
      id: "CVE-EXCLUSIVE",
      affected: [{
        package: { name: "org.example:lib", ecosystem: "Maven" },
        ranges: [{
          type: "ECOSYSTEM",
          events: [{ introduced: "1.0" }, { fixed: "1.9" }],
          representations: [{ range: "[1.0,1.9)" }],
        }],
      }],
    };
    const findings = matchVulnerabilities(pkg("1.5"), [exclusive]);
    expect(findings[0].fixedVersions).toContain("1.9");
    expect(matchVulnerabilities(pkg("1.9"), [exclusive])).toHaveLength(0);
    expect(buildFixPlan(findings, [exclusive]).fixable[0].targetVersion).toBe("1.9");
  });
});

// ─── Curated GHSA Version Lists ────────────────────────────

describe("curated GHSA version lists override coarse ranges", () => {
  // Modeled on GHSA-qh8g-58pp-2wxh (jetty-http CVE-2024-6763): the vendor-curated
  // list ends at 11.0.26 on the 11.x line (backport fix in 11.0.27) while the
  // auto-derived range [7.0.0, 12.0.12) numerically covers 11.0.29.
  const curatedEntry = {
    id: "GHSA-qh8g-58pp-2wxh",
    aliases: ["CVE-2024-6763"],
    ecosystems: ["Maven"],
    affected: [{
      package: { name: "org.eclipse.jetty:jetty-http", ecosystem: "Maven" },
      versions: ["11.0.24", "11.0.25", "11.0.26", "12.0.0", "12.0.11"],
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "7.0.0" }, { fixed: "12.0.12" }] }],
    }],
  };
  const pkg = (version: string) => [{
    ecosystem: "maven",
    name: "org.eclipse.jetty:jetty-http",
    version,
    manifestPath: "pom.xml",
  }];

  it("does not flag a backport-line version the curated list does not name", () => {
    expect(matchVulnerabilities(pkg("11.0.29"), [curatedEntry])).toHaveLength(0);
  });

  it("still flags versions named in the curated list", () => {
    const findings = matchVulnerabilities(pkg("11.0.24"), [curatedEntry]);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("GHSA-qh8g-58pp-2wxh");
  });

  it("keeps range union behavior for non-curated (CVE-keyed) entries", () => {
    const cveEntry = { ...curatedEntry, id: "CVE-2024-6763", aliases: ["GHSA-qh8g-58pp-2wxh"] };
    expect(matchVulnerabilities(pkg("11.0.29"), [cveEntry])).toHaveLength(1);
  });
});
