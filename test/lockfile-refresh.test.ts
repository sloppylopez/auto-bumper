import { describe, expect, it } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { lockRefreshCommands, poetryLockRetry } from "../src/lib/lockfile-refresh.ts";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "lock-refresh-"));
}

describe("lockfile refresh commands", () => {
  it("refreshes package-lock with npm and ignores a second JS lock", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "package-lock.json"), "{}");
    fs.writeFileSync(path.join(dir, "yarn.lock"), "");
    const labels = lockRefreshCommands(dir).map(c => c.label);
    expect(labels).toEqual(["npm install --package-lock-only"]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("picks yarn, pnpm, or bun when that lock is the only JS lock", () => {
    const yarn = tempDir();
    fs.writeFileSync(path.join(yarn, "yarn.lock"), "");
    expect(lockRefreshCommands(yarn).map(c => c.label)).toEqual(["yarn install --ignore-scripts"]);
    const pnpm = tempDir();
    fs.writeFileSync(path.join(pnpm, "pnpm-lock.yaml"), "");
    expect(lockRefreshCommands(pnpm).map(c => c.label)).toEqual(["pnpm install --lockfile-only"]);
    const bunDir = tempDir();
    fs.writeFileSync(path.join(bunDir, "bun.lock"), "");
    expect(lockRefreshCommands(bunDir).map(c => c.label)).toEqual(["bun install --lockfile-only --ignore-scripts"]);
    fs.rmSync(yarn, { recursive: true, force: true });
    fs.rmSync(pnpm, { recursive: true, force: true });
    fs.rmSync(bunDir, { recursive: true, force: true });
  });

  it("refreshes named crates and poetry without a full upgrade", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "Cargo.lock"), "");
    fs.writeFileSync(path.join(dir, "poetry.lock"), "");
    expect(lockRefreshCommands(dir, { cargoPackages: ["serde"] }).map(c => c.label)).toEqual([
      "cargo update -p serde",
      "poetry lock --no-update",
    ]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("uses the Poetry 2 lock command while retaining the Poetry 1 option", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "poetry.lock"), "");
    expect(lockRefreshCommands(dir, { poetryVersion: "2.0.0" }).map(c => c.label)).toEqual(["poetry lock"]);
    expect(lockRefreshCommands(dir, { poetryVersion: "1.8.5" }).map(c => c.label)).toEqual(["poetry lock --no-update"]);
    expect(lockRefreshCommands(dir).map(c => c.label)).toEqual(["poetry lock --no-update"]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("retries poetry lock once when Poetry 2 rejects --no-update", () => {
    expect(poetryLockRetry(["lock", "--no-update"], "The option \"--no-update\" does not exist")).toEqual(["lock"]);
    expect(poetryLockRetry(["lock", "--no-update"], "network down")).toBeNull();
    expect(poetryLockRetry(["lock"], "The option \"--no-update\" does not exist")).toBeNull();
  });

  it("does not run cargo update when no crate was bumped", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "Cargo.lock"), "");
    expect(lockRefreshCommands(dir).map(c => c.label)).toEqual([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("uses yarn lockfile-only mode for Berry and warns on classic", () => {
    const berry = tempDir();
    fs.writeFileSync(path.join(berry, "yarn.lock"), "__metadata:\n  version: 6\n");
    expect(lockRefreshCommands(berry).map(c => c.label)).toEqual(["yarn install --mode=update-lockfile"]);
    const classic = tempDir();
    fs.writeFileSync(path.join(classic, "yarn.lock"), "# yarn lockfile v1\n");
    const classicCmds = lockRefreshCommands(classic);
    expect(classicCmds.map(c => c.label)).toEqual(["yarn install --ignore-scripts"]);
    expect(classicCmds[0]?.warn).toContain("Yarn classic");
    fs.rmSync(berry, { recursive: true, force: true });
    fs.rmSync(classic, { recursive: true, force: true });
  });

  it("does nothing when the manifest has no lockfile", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "package.json"), "{}");
    fs.writeFileSync(path.join(dir, "requirements.txt"), "flask==1.0.0\n");
    expect(lockRefreshCommands(dir)).toEqual([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
