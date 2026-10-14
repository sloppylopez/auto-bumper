import type { Finding } from "../src/lib/types.ts";
import { sortBySeverity, SeverityOrder } from "../src/lib/types.ts";

const makeFinding = (overrides: Partial<Finding>): Finding => ({
  id: "GHSA-test",
  aliases: [],
  ecosystem: "npm",
  packageName: "lodash",
  installedVersion: "4.5.0",
  vulnerableRange: "<4.6.0",
  fixedVersions: ["4.6.0"],
  severity: "LOW",
  summary: "Test vulnerability",
  references: [],
  ...overrides,
});

describe("SeverityOrder", () => {
  it("assigns correct numeric values", () => {
    expect(SeverityOrder.CRITICAL).toBe(4);
    expect(SeverityOrder.HIGH).toBe(3);
    expect(SeverityOrder.MODERATE).toBe(2);
    expect(SeverityOrder.LOW).toBe(1);
    expect(SeverityOrder.UNKNOWN).toBe(0);
  });
});

describe("sortBySeverity", () => {
  it("empty array returns empty array", () => {
    expect(sortBySeverity([])).toEqual([]);
  });

  it("single item unchanged", () => {
    const f = [makeFinding({ severity: "HIGH" })];
    const result = sortBySeverity(f);
    expect(result.length).toBe(1);
    expect(result[0].id).toBe(f[0].id);
  });

  it("sorts CRITICAL > HIGH > MODERATE > LOW > UNKNOWN", () => {
    const findings: Finding[] = [
      makeFinding({ id: "low", severity: "LOW", packageName: "a" }),
      makeFinding({ id: "critical", severity: "CRITICAL", packageName: "b" }),
      makeFinding({ id: "high", severity: "HIGH", packageName: "c" }),
      makeFinding({ id: "moderate", severity: "MODERATE", packageName: "d" }),
      makeFinding({ id: "unknown", severity: "UNKNOWN", packageName: "e" }),
    ];
    const sorted = sortBySeverity(findings);
    expect(sorted[0].severity).toBe("CRITICAL");
    expect(sorted[1].severity).toBe("HIGH");
    expect(sorted[2].severity).toBe("MODERATE");
    expect(sorted[3].severity).toBe("LOW");
    expect(sorted[4].severity).toBe("UNKNOWN");
  });

  it("same severity sorts by packageName alphabetically", () => {
    const findings: Finding[] = [
      makeFinding({ id: "z", severity: "HIGH", packageName: "z-package" }),
      makeFinding({ id: "a", severity: "HIGH", packageName: "a-package" }),
      makeFinding({ id: "m", severity: "HIGH", packageName: "m-package" }),
    ];
    const sorted = sortBySeverity(findings);
    expect(sorted[0].packageName).toBe("a-package");
    expect(sorted[1].packageName).toBe("m-package");
    expect(sorted[2].packageName).toBe("z-package");
  });

  it("original array not mutated (immutability check)", () => {
    const findings: Finding[] = [
      makeFinding({ id: "low", severity: "LOW" }),
      makeFinding({ id: "high", severity: "HIGH" }),
    ];
    const originalOrder = findings.map(f => f.severity);
    sortBySeverity(findings);
    expect(findings.map(f => f.severity)).toEqual(originalOrder);
  });
});
