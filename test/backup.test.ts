import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { BACKUP_SUFFIX, LEGACY_BACKUP_SUFFIX } from "../src/lib/brand.ts";
import { backupFile, discardStaleBackup } from "../src/lib/backup.ts";

function withTempFile(content: string, run: (filePath: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-backup-"));
  const filePath = path.join(dir, "build.gradle");
  fs.writeFileSync(filePath, content, "utf-8");
  try {
    run(filePath);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("discardStaleBackup", () => {
  it("removes a backup that no longer matches the manifest", () => {
    withTempFile("version 1\n", filePath => {
      backupFile(filePath);
      expect(fs.existsSync(`${filePath}${BACKUP_SUFFIX}`)).toBe(true);
      // The manifest changed after the snapshot (a later run or manual edit).
      fs.writeFileSync(filePath, "version 2\n", "utf-8");
      discardStaleBackup(filePath);
      expect(fs.existsSync(`${filePath}${BACKUP_SUFFIX}`)).toBe(false);
    });
  });

  it("keeps a backup that still matches the manifest (interrupted run)", () => {
    withTempFile("version 1\n", filePath => {
      backupFile(filePath);
      discardStaleBackup(filePath);
      expect(fs.existsSync(`${filePath}${BACKUP_SUFFIX}`)).toBe(true);
    });
  });

  it("is a no-op when no backup exists and prunes legacy suffixes too", () => {
    withTempFile("version 1\n", filePath => {
      discardStaleBackup(filePath); // nothing to do
      expect(fs.existsSync(filePath)).toBe(true);
      fs.writeFileSync(`${filePath}${LEGACY_BACKUP_SUFFIX}`, "old content\n", "utf-8");
      discardStaleBackup(filePath);
      expect(fs.existsSync(`${filePath}${LEGACY_BACKUP_SUFFIX}`)).toBe(false);
    });
  });
});
