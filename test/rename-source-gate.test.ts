import { describe, expect, it } from "bun:test";
import {
  partitionRenamesBySourceNeed,
  reconcileRenamesWithSourceApproval,
  renameNeedsSourceMigration,
  SOURCE_BOUND_RENAME_SKIP_HINT,
} from "../src/lib/rename-source-gate.ts";
import { fixLoopBlockedMessage } from "../src/lib/manifest-overlay.ts";

const JACKSON_RENAME = {
  packageName: "com.fasterxml.jackson.core:jackson-databind",
  renameTo: "tools.jackson.core:jackson-databind",
  ecosystem: "maven",
};

const PLAIN_RENAME = {
  packageName: "old.group:widget",
  renameTo: "new.group:widget",
  ecosystem: "maven",
};

describe("renameNeedsSourceMigration", () => {
  it("flags Jackson databind rename", () => {
    expect(renameNeedsSourceMigration(JACKSON_RENAME)).toBe(true);
  });

  it("does not flag unknown plain rename", () => {
    expect(renameNeedsSourceMigration(PLAIN_RENAME)).toBe(false);
  });
});

describe("partitionRenamesBySourceNeed", () => {
  it("splits jackson vs plain", () => {
    const { needsSource, plain } = partitionRenamesBySourceNeed([JACKSON_RENAME, PLAIN_RENAME]);
    expect(needsSource).toEqual([JACKSON_RENAME]);
    expect(plain).toEqual([PLAIN_RENAME]);
  });
});

describe("reconcileRenamesWithSourceApproval", () => {
  it("skips source-bound renames when source not approved", () => {
    const { approved, skipped } = reconcileRenamesWithSourceApproval({
      needsSource: [JACKSON_RENAME],
      plain: [PLAIN_RENAME],
      sourceApproved: false,
    });
    expect(approved).toEqual([PLAIN_RENAME]);
    expect(skipped).toEqual([JACKSON_RENAME]);
  });

  it("keeps Jackson rename when source approved", () => {
    const { approved, skipped } = reconcileRenamesWithSourceApproval({
      needsSource: [JACKSON_RENAME],
      plain: [PLAIN_RENAME],
      sourceApproved: true,
    });
    expect(approved).toEqual([PLAIN_RENAME, JACKSON_RENAME]);
    expect(skipped).toEqual([]);
  });
});

describe("fixLoopBlockedMessage source-bound", () => {
  it("mentions both flags for source-bound renames", () => {
    const msg = fixLoopBlockedMessage({
      findingCount: 1,
      skippedMajors: 0,
      skippedRenames: 1,
      skippedSourceBoundRenames: 1,
    });
    expect(msg).toContain("--allow-renames");
    expect(msg).toContain("--allow-source-migrations");
    expect(msg).not.toMatch(/1 rename\(s\) need --allow-renames\.$/);
  });

  it("keeps plain rename hint when only non-source renames skipped", () => {
    const msg = fixLoopBlockedMessage({
      findingCount: 1,
      skippedMajors: 0,
      skippedRenames: 1,
      skippedSourceBoundRenames: 0,
    });
    expect(msg).toContain("--allow-renames");
    expect(msg).not.toContain("--allow-source-migrations");
  });
});

describe("SOURCE_BOUND_RENAME_SKIP_HINT", () => {
  it("points at source migrations flag", () => {
    expect(SOURCE_BOUND_RENAME_SKIP_HINT).toContain("--allow-source-migrations");
  });
});
