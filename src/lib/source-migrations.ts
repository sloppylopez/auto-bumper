/**
 * Source migrations for known coordinate renames (opt-in via --allow-source-migrations).
 */
import type { SourceMigrationConfig } from "./maven-renames.ts";
import {
  applyJavaImportMigrations,
  discardJavaImportBackups,
  restoreJavaImportBackups,
} from "./java-import-editor.ts";
import {
  applyJsImportMigrations,
  discardJsImportBackups,
  restoreJsImportBackups,
} from "./js-import-editor.ts";
import {
  applyPythonImportMigrations,
  discardPythonImportBackups,
  restorePythonImportBackups,
} from "./python-import-editor.ts";
import {
  applyRustImportMigrations,
  discardRustImportBackups,
  restoreRustImportBackups,
} from "./rust-import-editor.ts";

export interface SourceMigrationApplyResult {
  changed: string[];
  warnings: string[];
  byLanguage: Record<string, number>;
}

/** Human-readable summary for fix reports and dry-run. */
export function describeSourceMigrations(config: SourceMigrationConfig): string[] {
  const lines: string[] = [];

  if (config.clusters.length > 0) {
    lines.push(`Clusters: ${config.clusters.join(", ")}`);
  }

  addJavaLines(lines, config.java);
  addEcoSection(lines, "JavaScript/TypeScript", "package", config.javascript);
  addEcoSection(lines, "Python", "package", config.python);
  addEcoSection(lines, "Rust", "crate", config.rust);

  return lines;
}

/** Add Java migration description lines */
function addJavaLines(lines: string[], java: SourceMigrationConfig["java"]) {
  if (!java) return;
  lines.push(`Java: ${java.rules.length} import prefix rule(s)`);
  for (const rule of java.rules) {
    const except = rule.exceptPrefixes?.length
      ? ` (except ${rule.exceptPrefixes.join(", ")})`
      : "";
    lines.push(`  - ${rule.fromPrefix} -> ${rule.toPrefix}${except}`);
  }
  const globs = java.globs || ["src/main/java/**/*.java", "src/test/java/**/*.java"];
  lines.push(`  Globs: ${globs.join(", ")}`);
}

/** Add ecosystem-specific (JS/Python/Rust) migration description lines */
function addEcoSection(
  lines: string[],
  label: string,
  itemLabel: string,
  section: { rules?: Array<{ fromPackage: string; toPackage: string }>; globs?: string[] } | undefined,
) {
  if (!section?.rules) return;
  lines.push(`${label}: ${section.rules.length} ${itemLabel} rename(s)`);
  for (const rule of section.rules) {
    lines.push(`  - ${rule.fromPackage} -> ${rule.toPackage}`);
  }
  lines.push(`  Globs: ${(section.globs || []).join(", ")}`);
}

/** Apply known source rewrites for applied rename clusters. */
export function applySourceMigrations(
  projectRoot: string,
  config: SourceMigrationConfig,
): SourceMigrationApplyResult {
  const result: SourceMigrationApplyResult = {
    changed: [],
    warnings: [],
    byLanguage: {},
  };

  if (config.java) {
    const javaResult = applyJavaImportMigrations(
      projectRoot,
      config.java.rules,
      config.java.globs,
    );
    result.changed.push(...javaResult.changed);
    result.warnings.push(...javaResult.warnings);
    result.byLanguage.java = javaResult.changed.length;
  }

  if (config.javascript) {
    const jsResult = applyJsImportMigrations(
      projectRoot,
      config.javascript.rules,
      config.javascript.globs,
    );
    result.changed.push(...jsResult.changed);
    result.warnings.push(...jsResult.warnings);
    result.byLanguage.javascript = jsResult.changed.length;
  }

  if (config.python) {
    const pyResult = applyPythonImportMigrations(
      projectRoot,
      config.python.rules,
      config.python.globs,
    );
    result.changed.push(...pyResult.changed);
    result.warnings.push(...pyResult.warnings);
    result.byLanguage.python = pyResult.changed.length;
  }

  if (config.rust) {
    const rustResult = applyRustImportMigrations(
      projectRoot,
      config.rust.rules,
      config.rust.globs,
    );
    result.changed.push(...rustResult.changed);
    result.warnings.push(...rustResult.warnings);
    result.byLanguage.rust = rustResult.changed.length;
  }

  return result;
}

export function restoreSourceMigrationBackups(filePaths: string[]): number {
  return restoreJavaImportBackups(filePaths)
    + restoreJsImportBackups(filePaths)
    + restorePythonImportBackups(filePaths)
    + restoreRustImportBackups(filePaths);
}

export function discardSourceMigrationBackups(filePaths: string[]): void {
  discardJavaImportBackups(filePaths);
  discardJsImportBackups(filePaths);
  discardPythonImportBackups(filePaths);
  discardRustImportBackups(filePaths);
}
