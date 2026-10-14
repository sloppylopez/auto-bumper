/**
 * Gradle / Maven dependency health checks — mixed migrations, risky managed blocks.
 */
import fs from "node:fs";
import type { FixPlan } from "./fixer.ts";
import type { PackageRef } from "./types.ts";
import { GRADLE_MARKERS } from "./brand.ts";
import {
  mavenGroup,
  migrationsByCluster,
  siblingMigrations,
} from "./maven-renames.ts";

const PLATFORM_COORDS = new Set([
  "org.springframework.boot:spring-boot",
  "org.springframework:spring-core",
]);

function groupsOnClasspath(packages: PackageRef[]): Set<string> {
  const groups = new Set<string>();
  for (const pkg of packages) {
    if (pkg.ecosystem !== "maven") continue;
    const group = mavenGroup(pkg.name);
    if (group) groups.add(group);
  }
  return groups;
}

function mixedMigrationWarnings(groups: Set<string>): string[] {
  const warnings: string[] = [];
  for (const [clusterKey] of migrationsByCluster()) {
    const [fromGroup, toGroup] = clusterKey.split("|");
    if (groups.has(fromGroup) && groups.has(toGroup)) {
      warnings.push(
        `Mixed Maven coordinates during migration: ${fromGroup} and ${toGroup} both on classpath — align related artifacts.`,
      );
    }
  }
  return warnings;
}

/** Warn when resolved tree mixes old and new groups from a known migration. */
export function analyzeMavenPackages(packages: PackageRef[]): string[] {
  return mixedMigrationWarnings(groupsOnClasspath(packages));
}

export function analyzeBuildGradleFile(buildGradlePath: string): string[] {
  if (!fs.existsSync(buildGradlePath)) return [];
  return analyzeBuildGradleContent(fs.readFileSync(buildGradlePath, "utf-8"));
}

export function analyzeBuildGradleContent(content: string): string[] {
  const warnings: string[] = [];
  const groupsInFile = new Set<string>();

  for (const m of content.matchAll(/([a-z][a-z0-9_.-]{0,63}):[a-z][a-z0-9_.-]+/gm)) {
    groupsInFile.add(m[1]);
  }

  warnings.push(...mixedMigrationWarnings(groupsInFile));

  for (const { begin, end } of GRADLE_MARKERS) {
    const start = content.indexOf(begin);
    const stop = content.indexOf(end);
    if (start === -1 || stop === -1 || stop <= start) continue;

    const block = content.slice(start, stop);

    for (const [clusterKey] of migrationsByCluster()) {
      const fromGroup = clusterKey.split("|")[0];
      const escaped = fromGroup.replaceAll(".", String.raw`\.`);
      if (new RegExp(String.raw`exclude\s+group:\s*['"]${escaped}['"]`).test(block)) {
        warnings.push(
          `Managed block excludes ${fromGroup} — scan may look clean while transitive deps still need it. Verify with gradlew build.`,
        );
      }
    }

    const constraintRe = /implementation\(['"]([^'":]+:[^'":]+):([^'"]+)['"]\)/g;
    for (const m of block.matchAll(constraintRe)) {
      const coord = m[1];
      if (PLATFORM_COORDS.has(coord)) {
        warnings.push(
          `Managed constraint on ${coord}@${m[2]} is a transitive pin — prefer bumping platform plugin/BOM in build.gradle.`,
        );
      }
    }
  }

  return [...new Set(warnings)];
}

export function analyzeFixPlan(plan: FixPlan, packages: PackageRef[]): string[] {
  const warnings: string[] = [...analyzeMavenPackages(packages)];

  for (const c of plan.fixable) {
    if (PLATFORM_COORDS.has(c.packageName)) {
      warnings.push(
        `${c.packageName} bump to ${c.targetVersion} will likely become a managed constraint — bump platform plugin/BOM instead when possible.`,
      );
    }
  }

  for (const r of plan.renames) {
    if (!r.renameTo) continue;

    const siblings = siblingMigrations(r.packageName, r.renameTo);
    const presentSiblings = siblings.filter(s =>
      packages.some(p => p.name === s) && !plan.renames.some(x => x.packageName === s),
    );
    if (presentSiblings.length > 0) {
      warnings.push(
        `Coordinate rename ${r.packageName} -> ${r.renameTo} — also migrate: ${presentSiblings.join(", ")}`,
      );
    }

    if (r.isMajor) {
      warnings.push(
        `Major coordinate migration planned — run gradlew build (or mvn verify) after apply.`,
      );
    }
  }

  return [...new Set(warnings)];
}
