#!/usr/bin/env bun
/**
 * Auto-Bumper — Polyglot offline vulnerability scanner.
 *
 * Usage:
 *   scan [path] [--format markdown|json] [--ecosystem npm|crates.io|pypi|maven] [--offline]
 *   bun cli/scan.ts [path] [options]   (local dev)
 *
 * Exit codes: 0 clean, 1 vulns found, 2 error / nothing scannable
 */
import fs from "node:fs";
import { defaultSpinnerFactory } from "../src/lib/spinner.ts";
import { runAutoBumperScan, normalizeCliPath } from "../src/scan.ts";
import { reportMarkdown, reportJson } from "../src/lib/reporter.ts";
import { SUPPORTED_LOCKFILE_NAMES } from "../src/lib/parse-lockfile.ts";

const args = process.argv.slice(2);
const targetPath = args.find(a => !a.startsWith("--")) || ".";
const resolvedTarget = normalizeCliPath(targetPath);
// The cache (.auto-bumper) resolves from process.cwd(); anchor it to the target project so results do not depend on where the CLI was invoked.
if (fs.existsSync(resolvedTarget)) process.chdir(resolvedTarget);
const formatFlag = args.find(a => a.startsWith("--format"));
const outputFormat = formatFlag ? formatFlag.split("=")[1] : "markdown";
const hasJsonFlag = args.includes("--json");
const ecosystemFlag = args.find(a => a.startsWith("--ecosystem"));
const ecosystemFilter = ecosystemFlag ? ecosystemFlag.split("=")[1]?.toLowerCase() : null;
const offlineFlag = args.includes("--offline");

if (hasJsonFlag) console.error("Warning: --json flag deprecated, use --format json");

try {
  const { packages, findings, warnings } = await runAutoBumperScan(resolvedTarget, {
    ecosystemFilter,
    ora: defaultSpinnerFactory,
    offline: offlineFlag,
  });

  for (const w of warnings) console.log(w);

  if (packages.length === 0 && !ecosystemFilter) {
    console.error(
      `\nNo supported lockfiles detected. Supported: ${SUPPORTED_LOCKFILE_NAMES.join(", ")}`,
    );
    process.exit(2);
  }

  if (packages.length === 0 && ecosystemFilter) {
    console.error(`No packages scanned for --ecosystem=${ecosystemFilter}. See warnings above.`);
    process.exit(2);
  }

  if (outputFormat === "json" || hasJsonFlag) {
    console.log(reportJson(findings));
  } else {
    console.log(reportMarkdown(findings));
  }

  process.exit(findings.length > 0 ? 1 : 0);
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`Scan failed: ${msg}`);
  process.exit(2);
}
