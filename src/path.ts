import fs from "node:fs";
import path from "node:path";

/** Default cache folder name under project cwd (when AUTO_BUMPER_CACHE_DIR is unset). */
export const CACHE_DIR = ".auto-bumper";

/** Cache root — override with AUTO_BUMPER_CACHE_DIR for CI or shared caches. */
export function getCacheRoot(cwd: string = process.cwd()): string {
  const override = process.env.AUTO_BUMPER_CACHE_DIR?.trim();
  if (override) return path.resolve(override);
  return path.join(cwd, CACHE_DIR);
}

export function getOsvDbDir(cwd: string = process.cwd()): string {
  return path.join(getCacheRoot(cwd), "db", "osv");
}

/**
 * Git Bash eats backslashes in C:\dev\code\foo before Node sees argv.
 * C:\dev\code\my-app becomes C:devcodemyapp (\n = newline, glued).
 */
export function repairMangledCliPath(raw: string): string | null {
  const trimmed = String(raw).trim();
  const m = /^([A-Za-z]):([^/]+)$/.exec(trimmed);
  if (!m || process.platform !== "win32") return null;

  const drive = m[1].toUpperCase();
  const body = m[2];
  const candidates = new Set<string>();

  const add = (suffix: string) => {
    const p = `${drive}:/${suffix}`.replaceAll(String.raw`\"`, "/").replaceAll("//", "/");
    candidates.add(p);
  };

  if (body.startsWith("devcode")) {
    add(`dev/code/${body.slice("devcode".length)}`);
  }
  if (body.includes("devcode")) {
    add(body.replace("devcode", "dev/code/"));
  }

  const glued = /^(.*code)([a-z][\w.-]*)$/.exec(body);
  if (glued) {
    add(`${glued[1]}/${glued[2]}`);
    if (glued[1].startsWith("dev") && !glued[1].includes("/")) {
      add(`dev/code/${glued[2]}`);
    }
  }

  for (const c of candidates) {
    const resolved = path.resolve(c);
    if (fs.existsSync(resolved)) return resolved;
  }
  return null;
}

export function normalizeCliPath(raw: string): string {
  let p = String(raw).trim();
  if (!p) return path.resolve(p);

  p = p.replaceAll("\\", "/");

  const msys = /^\/([a-zA-Z])\/(.*)$/.exec(p);
  if (msys && process.platform === "win32") {
    p = `${msys[1].toUpperCase()}:/${msys[2]}`;
  }

  let resolved = path.resolve(p);

  if (process.platform === "win32" && /^[A-Za-z]:/.test(String(raw).trim()) && !fs.existsSync(resolved)) {
    const repaired = repairMangledCliPath(raw);
    if (repaired) return repaired;
  }

  return resolved;
}

/** True when target is root or a path inside it. Rejects `..` escapes. */
export function isInsideDir(root: string, target: string): boolean {
  const rel = path.relative(path.resolve(root), path.resolve(target));
  if (rel === "") return true;
  return !path.isAbsolute(rel) && rel.split(path.sep)[0] !== "..";
}

export function pathHint(raw: string): string {
  if (process.platform !== "win32") return "";
  const trimmed = String(raw).trim();
  if (/^[A-Za-z]:[^/\\]+$/.test(trimmed)) {
    return String.raw`Git Bash mangled this path. Use C:/dev/code/project, or quote: 'C:\dev\code\project'`;
  }
  if (/\\/.test(raw)) {
    return "Git Bash tip: use C:/dev/code/project (forward slashes)";
  }
  return "";
}
