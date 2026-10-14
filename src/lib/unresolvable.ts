import type { PackageRef } from "./types.ts";

/** An applied fix record that may need rolling back (shape of cli/fix.ts AppliedBump). */
export interface RollbackRecord {
  packageName: string;
  from: string;
  to: string;
  method: string;
  manifestPath?: string;
  isRename?: boolean;
}

/** Collect applied direct/constrained bumps matching an unresolved coordinate. */
function collectMatches<T extends RollbackRecord>(applied: T[], coord: string, out: T[]): void {
  for (const r of applied) {
    if (r.isRename) continue;
    if (r.method !== "direct" && r.method !== "constrained") continue;
    if (r.packageName.toLowerCase() === coord && !out.includes(r)) out.push(r);
  }
}

/**
 * Select applied bumps whose target version cannot be resolved from the project's repositories.
 *
 * `unresolved` entries are "group:name@requestedVersion" coordinates reported by the build
 * (e.g. Gradle FAILED nodes for yanked releases). A coordinate only counts when it is also
 * absent from the successfully resolved packages — a version may fail in one configuration
 * and resolve in another. Renames and non-bump methods cannot be rolled back automatically.
 */
export function selectUnresolvableRollbacks<T extends RollbackRecord>(
  applied: T[],
  unresolved: string[] | undefined,
  packages: PackageRef[],
): T[] {
  if (!unresolved || unresolved.length === 0) return [];

  const resolvedNames = new Set(packages.map(p => p.name.toLowerCase()));
  const out: T[] = [];
  for (const entry of unresolved) {
    const coord = entry.split("@")[0];
    if (!coord || resolvedNames.has(coord)) continue;
    collectMatches(applied, coord, out);
  }
  return out;
}
