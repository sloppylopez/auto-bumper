/**
 * Drop fix-plan items already satisfied on classpath or in build.gradle.
 */
import fs from "node:fs";
import { compareMavenVersion, comparePackageVersion } from "./matcher.ts";
import type { FixCandidate } from "./fixer.ts";
import type { PackageRef } from "./types.ts";
import {
  mavenGroup,
  migrationClusterKey,
  migrationsByCluster,
} from "./maven-renames.ts";

/** Migration clusters where old and new groups both appear on classpath. */
export function mixedMigrationClusters(packages: PackageRef[]): Set<string> {
  const groups = new Set<string>();
  for (const pkg of packages) {
    if (pkg.ecosystem !== "maven") continue;
    const g = mavenGroup(pkg.name);
    if (g) groups.add(g);
  }
  const mixed = new Set<string>();
  for (const key of migrationsByCluster().keys()) {
    const [fromGroup, toGroup] = key.split("|");
    if (groups.has(fromGroup) && groups.has(toGroup)) mixed.add(key);
  }
  return mixed;
}

function readManifestSnippets(paths: string[]): string[] {
  return paths
    .filter(p => fs.existsSync(p))
    .map(p => fs.readFileSync(p, "utf-8"));
}

function coordSatisfiedOnClasspath(
  packages: PackageRef[],
  coord: string,
  targetVersion: string,
): boolean {
  return packages.some(
    p => p.name === coord && compareMavenVersion(p.version, targetVersion) >= 0,
  );
}

function coordDeclaredInManifests(snippets: string[], coord: string): boolean {
  return snippets.some(s => s.includes(coord));
}

export function filterRedundantFixes(
  fixable: FixCandidate[],
  renames: FixCandidate[],
  packages: PackageRef[],
  manifestPaths: string[] = [],
): { fixable: FixCandidate[]; renames: FixCandidate[]; skipped: string[] } {
  const skipped: string[] = [];
  const snippets = readManifestSnippets(manifestPaths);
  const mixed = mixedMigrationClusters(packages);

  const outRenames = renames.filter(r => {
    if (!r.renameTo || !r.targetVersion) return true;
    const cluster = migrationClusterKey(r.packageName, r.renameTo);

    // Mixed classpath: finish migration (file edits + transitive excludes/constraints).
    if (mixed.has(cluster)) return true;

    const fromInFile = coordDeclaredInManifests(snippets, r.packageName);
    if (coordSatisfiedOnClasspath(packages, r.renameTo, r.targetVersion) && !fromInFile) {
      skipped.push(`rename ${r.packageName} (${r.renameTo} already resolved)`);
      return false;
    }
    if (
      coordDeclaredInManifests(snippets, r.renameTo)
      && !fromInFile
    ) {
      skipped.push(`rename ${r.packageName} (${r.renameTo} already in build file)`);
      return false;
    }
    return true;
  });

  const outFixable = fixable.filter(f => {
    if (!f.targetVersion) return true;
    if (comparePackageVersion(f.installedVersion, f.targetVersion, f.ecosystem || "maven") >= 0) {
      skipped.push(`bump ${f.packageName} (already at ${f.installedVersion})`);
      return false;
    }
    return true;
  });

  return { fixable: outFixable, renames: outRenames, skipped };
}

/** Renames needed to pin/exclude transitives when file migrated but classpath still mixed. */
export function renamesForMixedClasspathCompletion(
  renames: FixCandidate[],
  packages: PackageRef[],
): FixCandidate[] {
  const mixed = mixedMigrationClusters(packages);
  if (mixed.size === 0) return [];

  return renames.filter(r => {
    if (!r.renameTo || !r.targetVersion) return false;
    const cluster = migrationClusterKey(r.packageName, r.renameTo);
    if (!mixed.has(cluster)) return false;
    return packages.some(p => p.name === r.packageName);
  });
}

export function planSignature(
  fixable: Array<{ packageName: string; targetVersion: string | null }>,
  renames: Array<{ packageName: string; renameTo?: string; targetVersion: string | null }>,
): string {
  const parts = [
    ...fixable.map(f => `b:${f.packageName}@${f.targetVersion}`),
    ...renames.map(r => `r:${r.packageName}->${r.renameTo}@${r.targetVersion}`),
  ].sort((a, b) => a.localeCompare(b));
  return parts.join("|");
}
