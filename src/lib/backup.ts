import fs from "node:fs";
import { BACKUP_SUFFIX, LEGACY_BACKUP_SUFFIX } from "./brand.ts";

export function backupPath(filePath: string): string {
  return `${filePath}${BACKUP_SUFFIX}`;
}

/**
 * Snapshot original file once. Later calls keep the first bak so yolo / multi-file
 * passes can still restore the pre-session content.
 */
export function backupFile(filePath: string): string {
  const bak = backupPath(filePath);
  if (fs.existsSync(bak)) return bak;
  fs.copyFileSync(filePath, bak);
  return bak;
}

export function restoreFile(filePath: string): boolean {
  for (const suffix of [BACKUP_SUFFIX, LEGACY_BACKUP_SUFFIX]) {
    const bak = `${filePath}${suffix}`;
    if (!fs.existsSync(bak)) continue;
    fs.copyFileSync(bak, filePath);
    return true;
  }
  return false;
}

export function discardBackup(filePath: string): void {
  for (const suffix of [BACKUP_SUFFIX, LEGACY_BACKUP_SUFFIX]) {
    try {
      const bak = `${filePath}${suffix}`;
      if (fs.existsSync(bak)) fs.unlinkSync(bak);
    } catch {
      // best effort
    }
  }
}

/**
 * Run mutating work with restore-on-failure.
 * Call `prepare` (e.g. backup all targets) before `apply`.
 */
export function runApplyTransaction(opts: {
  prepare: () => void;
  apply: () => void;
  restore: () => void;
}): void {
  opts.prepare();
  try {
    opts.apply();
  } catch (err) {
    opts.restore();
    throw err;
  }
}
