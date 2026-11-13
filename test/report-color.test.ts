import {
  colorizeFixReport,
  formatUnresolvableSection,
  paint,
  stdoutColorEnabled,
  uniqueRollbackCount,
} from "../src/lib/report-color.ts";

const REPORT = [
  "# Auto-Bumper Maven Fix Report",
  "",
  "Unfixable 1 · Rolled back 2 · Applied 3 · Planned 4",
  "",
  "## Applied (3)",
  "",
  "- demo:lib: 1.0.0 -> 1.2.0 (direct) [GHSA-1]",
  "",
  "## Planned bumps (1)",
  "",
  "| Package | Current | Target | Major | Advisories |",
  "| demo:lib | 1.0.0 | 1.2.0 | no | GHSA-1 |",
  "",
  "## Skipped — target not resolvable (2)",
  "",
  "- demo:core: rolled back 1.0 -> 2.0 — version 2.0 not found in project repositories",
  "",
  "## Unfixable (1)",
  "",
  "- demo:old@1.0 — no fixed version in OSV (consider --exclude=demo:old)",
  "",
  "## Remaining vulnerabilities (1)",
  "",
  "| Package | Installed | Advisory |",
  "| `demo:old` | 1.0 | GHSA-2 |",
  "",
].join("\n");

describe("colorizeFixReport", () => {
  it("leaves the report plain when color is off", () => {
    expect(colorizeFixReport(REPORT, false)).toBe(REPORT);
  });

  it("paints problem sections red and yellow, progress green and cyan", () => {
    const painted = colorizeFixReport(REPORT, true);
    expect(painted).toContain("\u001b[1;31m## Unfixable (1)\u001b[0m");
    expect(painted).toContain("\u001b[1;31m## Remaining vulnerabilities (1)\u001b[0m");
    expect(painted).toContain("\u001b[1;33m## Skipped — target not resolvable (2)\u001b[0m");
    expect(painted).toContain("\u001b[1;32m## Applied (3)\u001b[0m");
    expect(painted).toContain("\u001b[1;36m## Planned bumps (1)\u001b[0m");
    expect(painted).toContain("\u001b[1m# Auto-Bumper Maven Fix Report\u001b[0m");
  });

  it("dims the advice after the dash and keeps the package name strong", () => {
    const painted = colorizeFixReport(REPORT, true);
    expect(painted).toContain("\u001b[1;31m- demo:old@1.0\u001b[0m");
    expect(painted).toContain("\u001b[2;31m — no fixed version in OSV (consider --exclude=demo:old)\u001b[0m");
  });

  it("colors each status count on its own", () => {
    const painted = colorizeFixReport(REPORT, true);
    expect(painted).toContain("\u001b[31mUnfixable 1\u001b[0m");
    expect(painted).toContain("\u001b[33mRolled back 2\u001b[0m");
    expect(painted).toContain("\u001b[32mApplied 3\u001b[0m");
    expect(painted).toContain("\u001b[36mPlanned 4\u001b[0m");
  });
});

describe("formatUnresolvableSection", () => {
  it("collapses identical rollbacks and keeps the event count", () => {
    const row = { packageName: "org.example:core", from: "1.0", to: "2.0" };
    const lines = formatUnresolvableSection([row, row, { packageName: "org.example:h2", from: "1.0", to: "2.0" }]);
    expect(lines[0]).toBe("## Skipped — target not resolvable (2 packages, 3 rollbacks)");
    expect(lines.some(line => line.includes("org.example:core") && line.includes(" ×2 —"))).toBe(true);
    expect(lines.some(line => line.includes("org.example:h2") && line.includes(" ×"))).toBe(false);
    expect(uniqueRollbackCount([row, row])).toBe(1);
  });

  it("keeps a single-event heading when nothing repeats", () => {
    const lines = formatUnresolvableSection([{ packageName: "org.example:core", from: "1.0", to: "2.0" }]);
    expect(lines[0]).toBe("## Skipped — target not resolvable (1)");
  });
});

describe("stdoutColorEnabled", () => {
  const previous = {
    NO_COLOR: process.env.NO_COLOR,
    FORCE_COLOR: process.env.FORCE_COLOR,
    TERM: process.env.TERM,
  };

  afterEach(() => {
    restore("NO_COLOR", previous.NO_COLOR);
    restore("FORCE_COLOR", previous.FORCE_COLOR);
    restore("TERM", previous.TERM);
  });

  it("turns color off for NO_COLOR and FORCE_COLOR=0", () => {
    delete process.env.FORCE_COLOR;
    process.env.NO_COLOR = "1";
    expect(stdoutColorEnabled()).toBe(false);
    delete process.env.NO_COLOR;
    process.env.FORCE_COLOR = "0";
    expect(stdoutColorEnabled()).toBe(false);
  });

  it("paints only when enabled", () => {
    expect(paint("Unfixable", "31", false)).toBe("Unfixable");
    expect(paint("Unfixable", "31", true)).toBe("\u001b[31mUnfixable\u001b[0m");
  });
});

function restore(name: "NO_COLOR" | "FORCE_COLOR" | "TERM", value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
