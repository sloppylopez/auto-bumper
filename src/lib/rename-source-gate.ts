/**
 * Couple coordinate renames that require source rewrites to source-migration approval.
 * Prevents applying Jackson-style deps+excludes without import migration.
 */
import { sourceMigrationsForAppliedRenames } from "./maven-renames.ts";

export interface RenameSourceGateInput {
  packageName: string;
  renameTo?: string;
  ecosystem?: string;
}

/** True when this rename's migration cluster defines source rewrite rules. */
export function renameNeedsSourceMigration(rename: RenameSourceGateInput): boolean {
  if (!rename.renameTo) return false;
  return sourceMigrationsForAppliedRenames([{
    packageName: rename.packageName,
    renameTo: rename.renameTo,
    ecosystem: rename.ecosystem,
  }]) !== null;
}

/** Split renames into those that need source migration vs plain coord moves. */
export function partitionRenamesBySourceNeed<T extends RenameSourceGateInput>(renames: T[]): {
  needsSource: T[];
  plain: T[];
} {
  const needsSource: T[] = [];
  const plain: T[] = [];
  for (const r of renames) {
    if (renameNeedsSourceMigration(r)) needsSource.push(r);
    else plain.push(r);
  }
  return { needsSource, plain };
}

/**
 * If source migrations are not approved, drop all source-bound renames.
 * Plain renames always pass through.
 */
export function reconcileRenamesWithSourceApproval<T extends RenameSourceGateInput>(opts: {
  needsSource: T[];
  plain: T[];
  sourceApproved: boolean;
}): { approved: T[]; skipped: T[] } {
  if (opts.sourceApproved || opts.needsSource.length === 0) {
    return { approved: [...opts.plain, ...opts.needsSource], skipped: [] };
  }
  return { approved: [...opts.plain], skipped: [...opts.needsSource] };
}

export const SOURCE_BOUND_RENAME_SKIP_HINT =
  "needs --allow-source-migrations (with --allow-renames)";
