/**
 * Overlay manifest direct-dependency versions onto lockfile scan results.
 * Used in fix-loop re-scans so npm/Rust apply passes see bumped package.json / Cargo.toml.
 */
import fs from "node:fs";
import path from "node:path";
import type { PackageRef } from "./types.ts";

export const MANIFEST_OVERLAY_WARNING =
  "Re-scan uses manifest overrides for direct deps; run npm install / cargo update for full lockfile accuracy.";

function stripSemverPrefix(version: string): string {
  return version.replace(/^[~^>=<]+/, "").trim();
}

/** Read direct dependency versions from package.json. */
export function readNpmManifestDirectDeps(packageJsonPath: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!fs.existsSync(packageJsonPath)) return out;

  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  for (const section of [pkg.dependencies, pkg.devDependencies]) {
    if (!section) continue;
    for (const [name, ver] of Object.entries(section)) {
      out.set(name, stripSemverPrefix(ver));
    }
  }
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
    const ver = m[2].replace(/^[=~^]+/, "");
    if (/^\d/.test(ver)) out.set(name, ver);
  }

  const tableRe = /^([A-Za-z0-9_-]+)\s*=\s*\{\s*version\s*=\s*"([^"]+)"/gm;
  while ((m = tableRe.exec(content)) !== null) {
    out.set(m[1], m[2].replace(/^[=~^]+/, ""));
  }

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

  if (npmDeps.size === 0 && cargoDeps.size === 0) {
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
