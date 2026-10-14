/**
 * Ecosystem filter for scan results.
 * Gradle-resolved deps use ecosystem "maven" + manifestPath build.gradle.
 */
import type { PackageRef } from "./types.ts";

function isGradleManifest(manifestPath: string | undefined): boolean {
  if (!manifestPath) return false;
  const norm = manifestPath.replaceAll("\\", "/");
  return norm.endsWith("build.gradle") || norm.endsWith("build.gradle.kts");
}

function isMavenManifest(manifestPath: string | undefined): boolean {
  if (!manifestPath) return false;
  const norm = manifestPath.replaceAll("\\", "/");
  return norm.endsWith("pom.xml");
}

/** Filter packages by CLI --ecosystem value. */
export function filterPackagesByEcosystem(
  packages: PackageRef[],
  ecosystemFilter: string | null | undefined,
): PackageRef[] {
  if (!ecosystemFilter) return packages;

  const filter = ecosystemFilter.toLowerCase();

  if (filter === "gradle") {
    return packages.filter(p => isGradleManifest(p.manifestPath));
  }

  if (filter === "maven") {
    return packages.filter(p =>
      p.ecosystem === "maven" && (isMavenManifest(p.manifestPath) || !isGradleManifest(p.manifestPath)),
    );
  }

  return packages.filter(p => p.ecosystem === filter);
}

/** Map fix project kind to scan --ecosystem filter. */
export function scanEcosystemFilterForKind(kind: string): string {
  if (kind === "gradle") return "gradle";
  if (kind === "maven") return "maven";
  return kind;
}
