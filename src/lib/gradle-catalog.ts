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
/** Read the TOML file, returning null when it is missing or unreadable. */
function readTomlOrNull(tomlPath: string): string | null {
  try {
    return fs.readFileSync(tomlPath, "utf-8");
  } catch {
    return null;
  }
}

/** Parse a `[versions]` line of the form `alias = "value"`. */
function recordVersion(versions: Map<string, string>, line: string): void {
  const m = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/.exec(line);
  if (m) versions.set(m[1], m[2]);
}

/** Parse a `[libraries]` inline-table body into the libraries map. */
function recordLibrary(
  libraries: Map<string, CatalogLibrary>,
  versions: Map<string, string>,
  alias: string,
  tableText: string,
): void {
  const module = /module\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
  if (!module) return;
  const versionRef = /version\.ref\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
  const inlineVersion = /version\s*=\s*"([^"]+)"/.exec(tableText)?.[1];
  const version = versionRef ? (versions.get(versionRef) ?? null) : (inlineVersion ?? null);
  libraries.set(alias, { alias, module, version });
}

/** Append a continuation line to a multi-line inline table; records the library once it closes. */
function appendToOpenTable(
  open: { alias: string; text: string },
  line: string,
  versions: Map<string, string>,
  libraries: Map<string, CatalogLibrary>,
): { alias: string; text: string } | null {
  const text = open.text + " " + line;
  if (!/\}\s*$/.test(text)) return { alias: open.alias, text };
  recordLibrary(libraries, versions, open.alias, text.slice(1));
  return null;
}

/** Mutable state carried across lines while parsing a catalog. */
interface CatalogLineState {
  table: string;
  open: { alias: string; text: string } | null; // multi-line inline table in progress
}

/** Apply one trimmed line to the parse state, recording any version or library it completes. */
function parseCatalogLine(
  state: CatalogLineState,
  line: string,
  versions: Map<string, string>,
  libraries: Map<string, CatalogLibrary>,
): CatalogLineState {
  if (state.open !== null) {
    return { table: state.table, open: appendToOpenTable(state.open, line, versions, libraries) };
  }
  const header = /^\[([^\]]+)\]$/.exec(line);
  if (header) return { table: header[1].trim(), open: null };
  if (!line || line.startsWith("#")) return state;
  if (state.table === "versions") {
    recordVersion(versions, line);
    return state;
  }
  if (state.table !== "libraries") return state;
  const head = /^([A-Za-z0-9_-]+)\s*=\s*\{(.*)$/.exec(line);
  if (!head) return state;
  if (head[2].includes("}")) {
    recordLibrary(libraries, versions, head[1], head[2]);
    return state;
  }
  return { table: state.table, open: { alias: head[1], text: "{" + head[2] } };
}

export function parseVersionCatalog(tomlPath: string): VersionCatalog | null {
  const text = readTomlOrNull(tomlPath);
  if (text === null) return null;
  const versions = new Map<string, string>();
  const libraries = new Map<string, CatalogLibrary>();

  let state: CatalogLineState = { table: "", open: null };
  for (const rawLine of text.split(/\r?\n/)) {
    state = parseCatalogLine(state, rawLine.trim(), versions, libraries);
  }
  return { versions, libraries };
}

/** Map a `libs.<a>.<b>` accessor path to its catalog alias (dots become dashes, per Gradle). */
export function resolveCatalogAccessor(catalog: VersionCatalog, accessorPath: string): CatalogLibrary | null {
  const alias = accessorPath.replaceAll(".", "-");
  return catalog.libraries.get(alias) ?? null;
}
