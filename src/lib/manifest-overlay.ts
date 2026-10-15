/**
 * Overlay manifest direct-dependency versions onto lockfile scan results.
 * Used in fix-loop re-scans so npm, Rust, and Python apply passes see bumped manifests.
 */
import fs from "node:fs";
import path from "node:path";
import type { PackageRef } from "./types.ts";
import { comparePEP440 } from "./matcher.ts";
import { normalizePackageName } from "./parse-lockfile.ts";

export const MANIFEST_OVERLAY_WARNING =
  "Re-scan uses manifest overrides for direct deps; run npm install / cargo update / poetry update for full lockfile accuracy.";

function stripSemverPrefix(version: string): string {
  return version.replace(/^[~^>=<]+/, "").trim();
}

function usableNpmVersion(spec: string): string | null {
  if (/^(workspace:|file:|link:|portal:|catalog:)/.test(spec)) return null;
  const ver = stripSemverPrefix(spec);
  return /^\d/.test(ver) ? ver : null;
}

/** Yarn glob keys and name@version keys become the package name install resolves. */
function overridePackageName(key: string): string {
  let name = key.startsWith("**/") ? key.slice(3) : key;
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash < 0) return name;
    const at = name.indexOf("@", slash + 1);
    return at < 0 ? name : name.slice(0, at);
  }
  const at = name.indexOf("@");
  return at < 0 ? name : name.slice(0, at);
}

interface NpmPackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  overrides?: Record<string, unknown>;
  resolutions?: Record<string, unknown>;
  pnpm?: { overrides?: Record<string, unknown> };
}

function lockfileKind(dir: string): "npm" | "yarn" | "pnpm" | "none" {
  const has = (name: string) => fs.existsSync(path.join(dir, name));
  if (has("package-lock.json")) return "npm";
  if (has("yarn.lock")) return "yarn";
  if (has("pnpm-lock.yaml")) return "pnpm";
  return "none";
}

function overrideRecord(pkg: NpmPackageJson, dir: string): Record<string, unknown> | undefined {
  const kind = lockfileKind(dir);
  if (kind === "yarn") return pkg.resolutions;
  if (kind === "pnpm") return pkg.pnpm?.overrides;
  return pkg.overrides;
}

function putStringVersions(section: Record<string, unknown> | undefined, out: Map<string, string>, rewriteKey: boolean): void {
  if (!section) return;
  for (const [rawName, ver] of Object.entries(section)) {
    if (typeof ver !== "string") continue;
    const usable = usableNpmVersion(ver);
    if (!usable) continue;
    out.set(rewriteKey ? overridePackageName(rawName) : rawName, usable);
  }
}

/** Read direct dependency versions from package.json, plus the lockfile's override map. */
export function readNpmManifestDirectDeps(packageJsonPath: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!fs.existsSync(packageJsonPath)) return out;

  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")) as NpmPackageJson;
  for (const section of [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies, pkg.peerDependencies]) {
    putStringVersions(section, out, false);
  }
  // Overrides win at install time, so they win on the re-scan too.
  putStringVersions(overrideRecord(pkg, path.dirname(packageJsonPath)), out, true);
  return out;
}

/** Read direct dependency versions from Cargo.toml (simple and table forms). */
export function readCargoManifestDirectDeps(cargoTomlPath: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!fs.existsSync(cargoTomlPath)) return out;

  const content = fs.readFileSync(cargoTomlPath, "utf-8");
  const simpleRe = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/gm;
  let m: RegExpExecArray | null;
  while ((m = simpleRe.exec(content)) !== null) {
    const name = m[1];
    const ver = stripCargoVersion(m[2]);
    if (/^\d/.test(ver)) out.set(name, ver);
  }

  const tableRe = /^([A-Za-z0-9_-]+)\s*=\s*\{\s*version\s*=\s*"([^"]+)"/gm;
  while ((m = tableRe.exec(content)) !== null) {
    const ver = stripCargoVersion(m[2]);
    if (/^\d/.test(ver)) out.set(m[1], ver);
  }

  return out;
}

function stripCargoVersion(spec: string): string {
  return spec.replace(/^(>=|<=|~=|\^|~|=|>|<)/, "");
}

function putPypiVersion(out: Map<string, string>, name: string, version: string): void {
  const ver = version.replace(/[*,]/g, "").trim();
  if (!/^\d/.test(ver)) return;
  const key = normalizePackageName(name, "pypi");
  const prev = out.get(key);
  if (!prev || comparePEP440(ver, prev) > 0) out.set(key, ver);
}

function isPoetryDepSection(section: string): boolean {
  return section === "tool.poetry.dependencies"
    || section === "tool.poetry.dev-dependencies"
    || (section.startsWith("tool.poetry.group.") && section.endsWith(".dependencies"));
}

function isPep621DepSection(section: string): boolean {
  return section === "project" || section.startsWith("project.optional-dependencies");
}

function collectPyprojectDeps(content: string, out: Map<string, string>): void {
  let section = "";
  for (const line of content.split("\n")) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (!isPoetryDepSection(section) && !isPep621DepSection(section)) continue;
    if (isPoetryDepSection(section)) {
      const assign = /^\s*(\w[\w.-]*)\s*=\s*"([^"]*)"/.exec(line);
      if (assign) {
        const op = /^(===|==|>=|<=|~=|!=|>|<|\^|~)/.exec(assign[2]);
        if (op?.[1] === "!=" || op?.[1] === "<" || op?.[1] === "<=") continue;
        const ver = op ? assign[2].slice(op[1].length) : assign[2];
        putPypiVersion(out, assign[1], ver);
        continue;
      }
    }
    const req = /^\s*"?(\w[\w.-]*)(?:\[[^\]]+\])?\s*(===|==|>=|<=|~=|!=|>|<)\s*([^"<\s,]+)/.exec(line);
    if (!req) continue;
    if (req[2] === "!=" || req[2] === "<" || req[2] === "<=") continue;
    putPypiVersion(out, req[1], req[3]);
  }
}

function collectRequirementsDeps(content: string, out: Map<string, string>): void {
  for (const raw of content.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const commentIdx = line.indexOf("#");
    if (commentIdx > 0) line = line.slice(0, commentIdx).trim();
    const spec = /^(\w[\w.-]*)(?:\[[^\]]+\])?\s*(===|==|>=|<=|~=|!=|>|<)\s*([^,\s#]+)/.exec(line);
    if (!spec) continue;
    if (spec[2] === "!=" || spec[2] === "<" || spec[2] === "<=") continue;
    putPypiVersion(out, spec[1], spec[3]);
  }
}

/** Direct versions from pyproject.toml and requirements.txt. Higher pin wins when both declare a name. */
export function readPythonManifestDirectDeps(projectRoot: string): Map<string, string> {
  const out = new Map<string, string>();
  const pyproject = path.join(projectRoot, "pyproject.toml");
  const requirements = path.join(projectRoot, "requirements.txt");
  if (fs.existsSync(pyproject)) collectPyprojectDeps(fs.readFileSync(pyproject, "utf-8"), out);
  if (fs.existsSync(requirements)) collectRequirementsDeps(fs.readFileSync(requirements, "utf-8"), out);
  return out;
}

export interface ManifestOverlayResult {
  packages: PackageRef[];
  overlaid: string[];
}

/**
 * Replace lockfile versions with manifest direct-dep versions where names match.
 */
export function overlayManifestDirectDeps(
  packages: PackageRef[],
  projectRoot: string,
): ManifestOverlayResult {
  const npmPath = path.join(projectRoot, "package.json");
  const cargoPath = path.join(projectRoot, "Cargo.toml");
  const npmDeps = readNpmManifestDirectDeps(npmPath);
  const cargoDeps = readCargoManifestDirectDeps(cargoPath);
  const pypiDeps = readPythonManifestDirectDeps(projectRoot);

  if (npmDeps.size === 0 && cargoDeps.size === 0 && pypiDeps.size === 0) {
    return { packages, overlaid: [] };
  }

  const overlaid: string[] = [];
  const next = packages.map(pkg => {
    if (pkg.ecosystem === "npm" && npmDeps.has(pkg.name)) {
      const manifestVer = npmDeps.get(pkg.name)!;
      if (manifestVer !== pkg.version) {
        overlaid.push(`${pkg.name}: ${pkg.version} -> ${manifestVer} (package.json)`);
        return { ...pkg, version: manifestVer };
      }
    }
    if (pkg.ecosystem === "crates.io" && cargoDeps.has(pkg.name)) {
      const manifestVer = cargoDeps.get(pkg.name)!;
      if (manifestVer !== pkg.version) {
        overlaid.push(`${pkg.name}: ${pkg.version} -> ${manifestVer} (Cargo.toml)`);
        return { ...pkg, version: manifestVer };
      }
    }
    if (pkg.ecosystem === "pypi") {
      const key = normalizePackageName(pkg.name, "pypi");
      const manifestVer = pypiDeps.get(key);
      if (manifestVer && manifestVer !== pkg.version) {
        overlaid.push(`${pkg.name}: ${pkg.version} -> ${manifestVer} (python manifest)`);
        return { ...pkg, version: manifestVer };
      }
    }
    return pkg;
  });

  return { packages: next, overlaid };
}

export function fixLoopBlockedMessage(opts: {
  findingCount: number;
  skippedMajors: number;
  skippedRenames: number;
  skippedSourceBoundRenames?: number;
}): string {
  const parts: string[] = [`Stopped: nothing applicable (${opts.findingCount} remaining).`];
  if (opts.skippedMajors > 0) {
    parts.push(`${opts.skippedMajors} major bump(s) need --allow-major.`);
  }
  if (opts.skippedRenames > 0) {
    const sourceBound = opts.skippedSourceBoundRenames ?? 0;
    if (sourceBound > 0) {
      parts.push(`${opts.skippedRenames} rename(s) need --allow-renames; ${sourceBound} of them also need --allow-source-migrations.`);
    } else {
      parts.push(`${opts.skippedRenames} rename(s) need --allow-renames.`);
    }
  }
  return parts.join(" ");
}
