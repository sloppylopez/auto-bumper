import type { Finding } from "../src/lib/types.ts";
import { reportMarkdown, reportJson, reportSummary, countBySeverity } from "../src/lib/reporter.ts";

const makeFinding = (overrides: Partial<Finding>): Finding => ({
  id: "GHSA-test",
  aliases: ["CVE-2024-1234"],
  ecosystem: "npm",
  packageName: "lodash",
  installedVersion: "4.5.0",
  vulnerableRange: "<4.6.0",
  fixedVersions: ["4.6.0"],
  severity: "LOW",
  summary: "Test vulnerability description here",
  references: ["https://example.com/cve"],
  ...overrides,
});

describe("reportMarkdown", () => {
  it("returns clean message for empty findings", () => {
    const output = reportMarkdown([]);
    expect(output).toContain("Clean");
  });

  it("produces markdown table with pipes and severity headers", () => {
    const findings = [makeFinding({ severity: "HIGH", packageName: "axios" })];
    const output = reportMarkdown(findings);
    expect(output).toContain("|");
    expect(output).toContain("High");
    expect(output).toContain("Package");
    expect(output).toContain("Version");
  });

  it("includes emoji indicators per severity", () => {
    const findings = [
      makeFinding({ severity: "CRITICAL", id: "c" }),
      makeFinding({ severity: "LOW", id: "l" }),
    ];
    const output = reportMarkdown(findings);
    expect(output).toContain("🔴");
    expect(output).toContain("🔵");
  });
});

describe("reportJson", () => {
  it("returns valid parseable JSON string", () => {
    const findings = [makeFinding()];
    const json = reportJson(findings);
    const parsed = JSON.parse(json);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].id).toBe("GHSA-test");
  });

  it("returns empty array JSON for no findings", () => {
    const json = reportJson([]);
    expect(JSON.parse(json)).toEqual([]);
  });
});

describe("reportSummary", () => {
  it("contains 'No vulnerabilities' for empty findings", () => {
    const output = reportSummary([]);
    expect(output).toContain("No vulnerabilities");
  });

  it("contains count and severity labels for findings", () => {
    const findings = [
      makeFinding({ severity: "CRITICAL", id: "c" }),
      makeFinding({ severity: "HIGH", id: "h" }),
    ];
    const output = reportSummary(findings);
    expect(output).toContain("2");
    expect(output).toContain("critical");
    expect(output).toContain("high");
  });
});

describe("countBySeverity", () => {
  it("returns correct counts per severity level", () => {
    const findings = [
      makeFinding({ severity: "CRITICAL", id: "c1" }),
      makeFinding({ severity: "CRITICAL", id: "c2" }),
      makeFinding({ severity: "HIGH", id: "h1" }),
      makeFinding({ severity: "LOW", id: "l1" }),
    ];
    const counts = countBySeverity(findings);
    expect(counts.CRITICAL).toBe(2);
    expect(counts.HIGH).toBe(1);
    expect(counts.LOW).toBe(1);
  });

  it("returns empty object for no findings", () => {
    expect(countBySeverity([])).toEqual({});
  });
});
