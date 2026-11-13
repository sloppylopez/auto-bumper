/**
 * BOM managed-version lookup for Gradle platform detection.
 *
 * Fetches the platform BOM's POM (e.g. io.quarkus.platform:quarkus-bom:3.33.4.1) from the
 * project's repositories (Maven Central as fallback), extracts its dependencyManagement
 * versions, and caches them per BOM version — a published BOM is immutable, so a cache
 * hit needs no TTL. All network access is best-effort: any failure yields null and the
 * caller keeps best-effort behavior (no pin cleanup, no pin filtering).
 */
import fs from "node:fs";
import path from "node:path";
import { extractRepoUrls, fetchText, MAVEN_CENTRAL, stripTrailingSlashes } from "./repo-metadata.ts";
import { getCacheRoot } from "../path.ts";
import { findStaleManagedPins } from "./gradle-editor.ts";
import type { StaleManagedPin } from "./gradle-editor.ts";
import { isVersionAffectedByAdvisories } from "./matcher.ts";
import type { AdvisoryEntry } from "./types.ts";

/**
 * Managed versions declared by a BOM POM's <dependencyManagement> sections.
 * Key: "groupId:artifactId", value: version with ${property} references resolved.
 * Import-scoped (nested BOM) entries and unresolvable versions are skipped. Pure — unit-testable.
 */
/** `<profiles>` at `index`, not `<profile>`. */
function profilesTagAt(content: string, index: number): { close: boolean; end: number } | null {
  const close = content.startsWith("</", index);
  const nameAt = index + (close ? 2 : 1);
  if (!content.startsWith("profiles", nameAt)) return null;
  const after = nameAt + "profiles".length;
  const next = content[after];
  if (next !== ">" && next !== "/" && next !== " " && next !== "\t" && next !== "\n" && next !== "\r") return null;
  const gt = content.indexOf(">", after);
  if (gt === -1) return null;
  return { close: close || content[gt - 1] === "/", end: gt + 1 };
}

/** End index of a `<!-- -->` or `<![CDATA[ ]]>` section starting at `i`; null when neither. */
function skipXmlSection(xml: string, i: number): number | null {
  if (xml.startsWith("<!--", i)) {
    const end = xml.indexOf("-->", i + 4);
    return end === -1 ? xml.length : end + 3;
  }
  if (xml.startsWith("<![CDATA[", i)) {
    const end = xml.indexOf("]]>", i + 9);
    return end === -1 ? xml.length : end + 3;
  }
  return null;
}

/** Drop every `<profiles>` section. Activation is not evaluated. Comments and CDATA do not end the section. */
function stripProfiles(xml: string): string {
  let out = "";
  let i = 0;
  let depth = 0;
  while (i < xml.length) {
    const skip = skipXmlSection(xml, i);
    if (skip !== null) {
      out += depth === 0 ? xml.slice(i, skip) : "";
      i = skip;
      continue;
    }
    const tag = xml[i] === "<" ? profilesTagAt(xml, i) : null;
    if (!tag) {
      out += depth === 0 ? xml[i]! : "";
      i++;
      continue;
    }
    depth = tag.close ? Math.max(0, depth - 1) : depth + 1;
    i = tag.end;
  }
  return out;
}

export function parseBomManagedVersions(pomXml: string): Map<string, string> {
  const out = new Map<string, string>();
  const unconditionalPom = stripProfiles(pomXml);
  const props = parsePomProperties(unconditionalPom);

  /** Resolve ${property} references (up to 3 nested levels). Null when unresolvable. */
  const resolveRef = (value: string): string | null => {
    let v = value.trim();
    for (let i = 0; i < 3; i++) {
      const m = /^\$\{([^}]+)\}$/.exec(v);
      if (!m) return v;
      const next = props.get(m[1]!);
      if (next === undefined) return null;
      v = next.trim();
    }
    return /\$\{[^}]+\}/.test(v) ? null : v;
  };

  for (const dm of unconditionalPom.matchAll(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g)) {
    const section = dm[0]!;
    for (const dep of section.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
      const body = dep[1]!;
      const scope = tagValue(body, "scope");
      const type = tagValue(body, "type");
      if (scope === "import" || type === "pom") continue; // nested BOM — not a managed version
      const g = tagValue(body, "groupId");
      const a = tagValue(body, "artifactId");
      const v = tagValue(body, "version");
      if (!g || !a || !v) continue;
      const group = resolveRef(g);
      const artifact = resolveRef(a);
      const version = resolveRef(v);
      if (!group || !artifact || !version) continue; // unresolvable property — best-effort skip
      const key = `${group}:${artifact}`;
      if (!out.has(key)) out.set(key, version); // first declaration wins (Maven semantics)
    }
  }
  return out;
}

/** <properties> entries of a POM (name → literal value). */
function parsePomProperties(pomXml: string): Map<string, string> {
  const props = new Map<string, string>();
  const m = /<properties>([\s\S]*?)<\/properties>/.exec(pomXml);
  if (!m) return props;
  for (const p of m[1]!.matchAll(/<([A-Za-z][\w.-]*)>([^<]*)</g)) {
    props.set(p[1]!, p[2]!.trim());
  }
  return props;
}

/** Value of one <tag>...</tag> inside a dependency entry, trimmed. Null when absent. */
function tagValue(depBody: string, tag: string): string | null {
  const m = new RegExp(`<${tag}>([^<]+)</${tag}>`).exec(depBody);
  return m ? m[1]!.trim() : null;
}

/** Cache directory for parsed BOM maps (under the project's .auto-bumper root). */
function bomCacheDir(): string {
  return path.join(getCacheRoot(), "db", "bom");
}

function bomCachePath(group: string, artifact: string, version: string): string {
  const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(bomCacheDir(), `${safe(group)}__${safe(artifact)}__${safe(version)}.json`);
}

function readCachedBomMap(cachePath: string): Map<string, string> | null {
  try {
    const raw = fs.readFileSync(cachePath, "utf-8");
    const entries = JSON.parse(raw) as Array<[string, string]>;
    if (!Array.isArray(entries)) return null;
    return new Map(entries);
  } catch {
    return null; // missing or corrupt cache — treat as miss
  }
}

/** Atomic replace (Windows-safe). Cache write failure is not fatal. */
function writeCachedBomMap(cachePath: string, map: Map<string, string>): void {
  try {
    fs.mkdirSync(path.dirname(cachePath), { recursive: true });
    const tmp = `${cachePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([...map.entries()]));
    fs.renameSync(tmp, cachePath);
  } catch {
    // The parsed map is still returned to the caller.
  }
}

/**
 * Managed versions of a platform BOM as published in its POM. Cached per BOM version under
 * .auto-bumper/db/bom (BOMs are immutable once published). Null when no repository served a
 * parseable BOM POM (offline, auth failure, unknown layout) — callers keep best-effort behavior.
 */
export async function fetchBomManagedVersions(
  manifestPath: string,
  group: string,
  artifact: string,
  version: string,
): Promise<Map<string, string> | null> {
  const cachePath = bomCachePath(group, artifact, version);
  const cached = readCachedBomMap(cachePath);
  if (cached) return cached;

  let bases = extractRepoUrls(manifestPath, "gradle");
  if (!bases.some(b => stripTrailingSlashes(b) === MAVEN_CENTRAL)) bases.push(MAVEN_CENTRAL);
  const groupPath = group.replaceAll(".", "/");
  for (const base of bases) {
    const url = `${stripTrailingSlashes(base)}/${groupPath}/${artifact}/${version}/${artifact}-${version}.pom`;
    const pom = await fetchText(url);
    if (!pom) continue;
    const map = parseBomManagedVersions(pom);
    if (map.size === 0) continue; // not a BOM, or no resolvable versions — try the next repository
    writeCachedBomMap(cachePath, map);
    return map;
  }
  return null;
}

/**
 * Stale managed pins whose removal would reintroduce a known vulnerability: the BOM-managed
 * version is affected while the pinned version is not (e.g. a downgrade escape below
 * `introduced` when no forward fix exists). These must survive BOM pin cleanup. Pure — unit-testable.
 */
export function computeProtectedPins(
  content: string,
  bomManaged: ReadonlyMap<string, string>,
  advisories: readonly AdvisoryEntry[],
): Map<string, StaleManagedPin> {
  const protectedPins = new Map<string, StaleManagedPin>();
  for (const stale of findStaleManagedPins(content, bomManaged)) {
    // Probe each version in its own matcher call: matchVulnerabilities dedupes findings
    // per (advisory, package), so a single two-version probe would collapse to one finding.
    if (
      isVersionAffectedByAdvisories(stale.packageName, stale.bomVersion, "maven", advisories) &&
      !isVersionAffectedByAdvisories(stale.packageName, stale.version, "maven", advisories)
    ) {
      protectedPins.set(stale.packageName, stale);
    }
  }
  return protectedPins;
}
