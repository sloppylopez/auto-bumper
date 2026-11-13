/**
 * Rewrite the lockfile after a manifest bump.
 * Overlay alone leaves package-lock.json, yarn.lock, pnpm-lock.yaml,
 * bun.lock, Cargo.lock, and poetry.lock pinning the vulnerable version.
 */

import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { windowsBatchLaunch } from "./parse-lockfile.ts";

export interface LockRefreshCommand {
  bin: string;
  args: string[];
  /** Human-readable command, without a shell. */
  label: string;
  warn?: string;
}

export interface LockRefreshResult {
  label: string;
  ok: boolean;
  detail: string;
  /** Set when the command is broader than a lockfile-only rewrite. */
  warn?: string;
}

export interface LockRefreshOptions {
  /** Crates to pass to `cargo update -p`. Empty skips Cargo so the whole lock is not rewritten. */
  cargoPackages?: string[];
  /** Detected Poetry version; version 2 no longer supports --no-update. */
  poetryVersion?: string;
}

function detectPoetryVersion(dir: string): string | undefined {
  const bins = process.platform === "win32" ? ["poetry.exe", "poetry.cmd", "poetry"] : ["poetry"];
  for (const bin of bins) {
    const result = spawnCaptured(bin, ["--version"], { cwd: dir, timeout: 5_000 });
    if (result.error || result.status !== 0) continue;
    const major = /\b(\d+)\.\d+(?:\.\d+)?\b/.exec(`${result.stdout || ""} ${result.stderr || ""}`)?.[1];
    if (major) return major;
  }
  return undefined;
}

/** Poetry 2 rejects `--no-update`. Return the retry argv, or null when this failure is something else. */
export function poetryLockRetry(args: string[], detail: string): string[] | null {
  if (!args.includes("--no-update")) return null;
  if (!/no-update/i.test(detail)) return null;
  if (!/does not exist|no such option|unrecognized|unknown option/i.test(detail)) return null;
  return args.filter(arg => arg !== "--no-update");
}

function binName(name: string): string {
  if (process.platform !== "win32") return name;
  // Node does not resolve .cmd shims unless the extension is explicit.
  if (name === "npm" || name === "yarn" || name === "pnpm") return `${name}.cmd`;
  return name;
}

/** Yarn Berry lock (v2+) can update the lockfile without installing. Classic cannot. */
function yarnBerryLock(dir: string): boolean {
  if (fs.existsSync(path.join(dir, ".yarnrc.yml"))) return true;
  try {
    const head = fs.readFileSync(path.join(dir, "yarn.lock"), "utf8").slice(0, 800);
    if (/yarn lockfile v1/.test(head)) return false;
    return /__metadata:/.test(head);
  } catch {
    return false;
  }
}

/** Commands for lockfiles that already exist in dir. One JS manager, then Cargo and Poetry. */
export function lockRefreshCommands(dir: string, opts: LockRefreshOptions = {}): LockRefreshCommand[] {
  const has = (name: string) => fs.existsSync(path.join(dir, name));
  const commands: LockRefreshCommand[] = [];
  if (has("package-lock.json")) {
    commands.push({
      bin: binName("npm"),
      args: ["install", "--package-lock-only", "--ignore-scripts"],
      label: "npm install --package-lock-only",
    });
  } else if (has("yarn.lock")) {
    if (yarnBerryLock(dir)) {
      commands.push({
        bin: binName("yarn"),
        args: ["install", "--mode=update-lockfile"],
        label: "yarn install --mode=update-lockfile",
      });
    } else {
      commands.push({
        bin: binName("yarn"),
        args: ["install", "--ignore-scripts"],
        label: "yarn install --ignore-scripts",
        warn: "Yarn classic has no lockfile-only install; this runs a full install with scripts ignored.",
      });
    }
  } else if (has("pnpm-lock.yaml")) {
    commands.push({
      bin: binName("pnpm"),
      args: ["install", "--lockfile-only", "--ignore-scripts"],
      label: "pnpm install --lockfile-only",
    });
  } else if (has("bun.lock")) {
    commands.push({
      bin: binName("bun"),
      args: ["install", "--lockfile-only", "--ignore-scripts"],
      label: "bun install --lockfile-only --ignore-scripts",
    });
  }
  if (has("Cargo.lock")) {
    const crates = [...new Set((opts.cargoPackages ?? []).filter(Boolean))];
    if (crates.length > 0) {
      const flags = crates.flatMap(name => ["-p", name]);
      commands.push({
        bin: binName("cargo"),
        args: ["update", ...flags],
        label: `cargo update ${flags.join(" ")}`,
      });
    }
  }
  if (has("poetry.lock")) {
    const poetry2 = Number.parseInt(opts.poetryVersion || "", 10) >= 2;
    const args = poetry2 ? ["lock"] : ["lock", "--no-update"];
    commands.push({
      bin: binName("poetry"),
      args,
      label: `poetry ${args.join(" ")}`,
    });
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
    const launch = windowsBatchLaunch(executable, args);
    try {
      return childProcess.spawnSync(launch.file, launch.args, {
        ...base,
        env: launch.env,
        windowsVerbatimArguments: launch.windowsVerbatimArguments,
      });
    } finally {
      launch.cleanup();
    }
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
export function refreshProjectLocks(dir: string, timeoutMs = 300_000, opts: LockRefreshOptions = {}): LockRefreshResult[] {
  const resolvedOpts = opts.poetryVersion || !fs.existsSync(path.join(dir, "poetry.lock"))
    ? opts
    : { ...opts, poetryVersion: detectPoetryVersion(dir) };
  return lockRefreshCommands(dir, resolvedOpts).map(command => {
    let result = spawnCaptured(command.bin, command.args, { cwd: dir, timeout: timeoutMs });
    let label = command.label;
    const retry = result.status === 0 && !result.error ? null : poetryLockRetry(command.args, failureDetail(result));
    if (retry) {
      result = spawnCaptured(command.bin, retry, { cwd: dir, timeout: timeoutMs });
      label = `poetry ${retry.join(" ")}`;
    }
    const warn = command.warn;
    if (result.status === 0 && !result.error) return { label, ok: true, detail: "", ...(warn ? { warn } : {}) };
    return { label, ok: false, detail: failureDetail(result), ...(warn ? { warn } : {}) };
  });
}
