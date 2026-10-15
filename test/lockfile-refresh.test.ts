import { describe, expect, it } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { lockRefreshCommands } from "../src/lib/lockfile-refresh.ts";

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
    expect(lockRefreshCommands(bunDir).map(c => c.label)).toEqual(["bun install --lockfile-only"]);
    fs.rmSync(yarn, { recursive: true, force: true });
    fs.rmSync(pnpm, { recursive: true, force: true });
    fs.rmSync(bunDir, { recursive: true, force: true });
  });

  it("refreshes Cargo.lock and poetry.lock together", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "Cargo.lock"), "");
    fs.writeFileSync(path.join(dir, "poetry.lock"), "");
    expect(lockRefreshCommands(dir).map(c => c.label)).toEqual(["cargo update", "poetry lock"]);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("does nothing when the manifest has no lockfile", () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, "package.json"), "{}");
    fs.writeFileSync(path.join(dir, "requirements.txt"), "flask==1.0.0\n");
    expect(lockRefreshCommands(dir)).toEqual([]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
