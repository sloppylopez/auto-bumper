/**
 * Rewrite the lockfile after a manifest bump.
 * Overlay alone leaves package-lock.json, yarn.lock, pnpm-lock.yaml,
 * bun.lock, Cargo.lock, and poetry.lock pinning the vulnerable version.
 */

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { windowsBatchArgs } from "./parse-lockfile.ts";

export interface LockRefreshCommand {
  bin: string;
  args: string[];
  /** Human-readable command, without a shell. */
  label: string;
}

export interface LockRefreshResult {
  label: string;
  ok: boolean;
  detail: string;
}

function binName(name: string): string {
  if (process.platform !== "win32") return name;
  // Node does not resolve .cmd shims unless the extension is explicit.
  if (name === "npm" || name === "yarn" || name === "pnpm") return `${name}.cmd`;
  return name;
}

/** Commands for lockfiles that already exist in dir. One JS manager, then Cargo and Poetry. */
export function lockRefreshCommands(dir: string): LockRefreshCommand[] {
  const has = (name: string) => fs.existsSync(path.join(dir, name));
  const commands: LockRefreshCommand[] = [];
  if (has("package-lock.json")) {
    commands.push({
      bin: binName("npm"),
      args: ["install", "--package-lock-only", "--ignore-scripts"],
      label: "npm install --package-lock-only",
    });
  } else if (has("yarn.lock")) {
    commands.push({
      bin: binName("yarn"),
      args: ["install", "--ignore-scripts"],
      label: "yarn install --ignore-scripts",
    });
  } else if (has("pnpm-lock.yaml")) {
    commands.push({
      bin: binName("pnpm"),
      args: ["install", "--lockfile-only", "--ignore-scripts"],
      label: "pnpm install --lockfile-only",
    });
  } else if (has("bun.lock")) {
    commands.push({
      bin: binName("bun"),
      args: ["install", "--lockfile-only"],
      label: "bun install --lockfile-only",
    });
  }
  if (has("Cargo.lock")) {
    commands.push({ bin: binName("cargo"), args: ["update"], label: "cargo update" });
  }
  if (has("poetry.lock")) {
    commands.push({ bin: binName("poetry"), args: ["lock"], label: "poetry lock" });
  }
  return commands;
}

function spawnCaptured(
  executable: string,
  args: string[],
  opts: { cwd: string; timeout: number },
): childProcess.SpawnSyncReturns<string> {
  const base = {
    encoding: "utf-8" as const,
    timeout: opts.timeout,
    cwd: opts.cwd,
    maxBuffer: 10 * 1024 * 1024,
    windowsHide: true,
    shell: false as const,
  };
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(executable)) {
    const comspec = process.env.ComSpec || "cmd.exe";
    return childProcess.spawnSync(comspec, windowsBatchArgs(executable, args), {
      ...base,
      windowsVerbatimArguments: true,
    });
  }
  return childProcess.spawnSync(executable, args, base);
}

function failureDetail(result: childProcess.SpawnSyncReturns<string>): string {
  if (result.error) return result.error.message;
  const text = `${result.stderr || ""}\n${result.stdout || ""}`.trim();
  const tail = text.split(/\r?\n/).filter(Boolean).slice(-4).join(" ");
  return (tail || `exit ${result.status}`).slice(0, 400);
}

/** Run every lock refresh for dir. Empty when the project has no lockfile. */
export function refreshProjectLocks(dir: string, timeoutMs = 300_000): LockRefreshResult[] {
  return lockRefreshCommands(dir).map(command => {
    const result = spawnCaptured(command.bin, command.args, { cwd: dir, timeout: timeoutMs });
    if (result.status === 0 && !result.error) return { label: command.label, ok: true, detail: "" };
    return { label: command.label, ok: false, detail: failureDetail(result) };
  });
}
