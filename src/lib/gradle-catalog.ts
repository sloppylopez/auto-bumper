/**
 * Gradle version catalogs (libs.versions.toml) — discovery and lookup.
 *
 * The default `libs` catalog lives at `<buildRoot>/gradle/libs.versions.toml`, where the build
 * root is the directory holding settings.gradle[.kts] (or the wrapper, when no settings file
 * exists). A subproject of a multi-module build therefore resolves its catalog above itself; an
 * included build has its own root and must not see the outer build's catalog.
 */
import fs from "node:fs";
import path from "node:path";

const CATALOG_RELS = ["gradle/libs.versions.toml", "libs.versions.toml"];
/** Hard cap on the walk-up so a marker-less tree can never reach an unrelated catalog far away. */
const MAX_WALK_DEPTH = 8;

function isBuildRootMarker(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, "settings.gradle")) ||
    fs.existsSync(path.join(dir, "settings.gradle.kts")) ||
    fs.existsSync(path.join(dir, "gradlew")) ||
    fs.existsSync(path.join(dir, "gradlew.bat"))
  );
}

/**
 * Locate the version catalog for a Gradle build file. Own directory first (a subproject may be
 * the root of its own included build), then up to — and including — the nearest ancestor with a
 * settings file or wrapper. When no marker is found at all, only the own directory is checked:
 * without a settings file the project's own directory IS the build root.
 */
export function findVersionCatalog(buildFile: string): string | null {
  const start = path.dirname(path.resolve(buildFile));
  let rootLevel: string | null = null;
  let probe = start;
  for (let depth = 0; depth <= MAX_WALK_DEPTH; depth++) {
    if (isBuildRootMarker(probe)) {
      rootLevel = probe;
      break;
    }
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  let level = start;
  for (;;) {
    for (const rel of CATALOG_RELS) {
      const candidate = path.join(level, rel);
      if (fs.existsSync(candidate)) return candidate;
    }
    if (rootLevel === null || level === rootLevel) break;
    const parent = path.dirname(level);
    if (parent === level) break;
    level = parent;
  }
  return null;
}

export interface CatalogLibrary {
  alias: string;
  /** Maven coordinate "group:artifact". */
  module: string;
  /** Resolved version (version.ref already dereferenced); null when the entry pins no version. */
  version: string | null;
}

export interface VersionCatalog {
  versions: Map<string, string>;
  libraries: Map<string, CatalogLibrary>;
}

/**
 * Parse the `[versions]` and `[libraries]` tables of a libs.versions.toml. Minimal line-based
 * TOML: double-quoted values, inline tables (optionally spanning lines), `#` comments ignored by
 * anchoring on quoted values. Other tables are skipped.
 */
export function parseVersionCatalog(tomlPath: string): VersionCatalog | null {
  let text: string;
  try {
    text = fs.readFileSync(tomlPath, "utf-8");
  } catch {
    return null;
  }
  const versions = new Map<string, string>();
  const libraries = new Map<string, CatalogLibrary>();

  const recordLibrary = (alias: string, tableText: string): void => {
    const module = /module\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
    if (!module) return;
    const versionRef = /version\.ref\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
    const inlineVersion = /version\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
    const version = versionRef ? (versions.get(versionRef) ?? null) : (inlineVersion ?? null);
    libraries.set(alias, { alias, module, version });
  };

  let table = "";
  let openTable: { alias: string; text: string } | null = null; // multi-line inline table
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (openTable !== null) {
      openTable.text += " " + line;
      if (!/\}\s*$/.test(openTable.text)) continue;
      recordLibrary(openTable.alias, openTable.text.slice(1));
      openTable = null;
      continue;
    }
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      table = header[1].trim();
      continue;
    }
    if (!line || line.startsWith("#")) continue;
    if (table === "versions") {
      const m = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/.exec(line);
      if (m) versions.set(m[1], m[2]);
      continue;
    }
    if (table === "libraries") {
      const head = /^([A-Za-z0-9_-]+)\s*=\s*\{(.*)$/.exec(line);
      if (!head) continue;
      if (head[2].includes("}")) {
        recordLibrary(head[1], head[2]);
      } else {
        openTable = { alias: head[1], text: "{" + head[2] };
      }
    }
  }
  return { versions, libraries };
}

/** Map a `libs.<a>.<b>` accessor path to its catalog alias (dots become dashes, per Gradle). */
export function resolveCatalogAccessor(catalog: VersionCatalog, accessorPath: string): CatalogLibrary | null {
  const alias = accessorPath.split(".").join("-");
  return catalog.libraries.get(alias) ?? null;
}
