import fs from "node:fs";
import { compareMavenVersion } from "./matcher.ts";

/**
 * Repository metadata queries used to re-target fixes when the OSV fixed version
 * is not available in the project's repositories (e.g. yanked releases).
 * All network access is best-effort: any failure yields null and the caller falls
 * back to a safe rollback.
 */

const MAVEN_CENTRAL = "https://repo.maven.apache.org/maven2";

/** Extract repository base URLs declared in a Gradle or Maven manifest. */
export function extractRepoUrls(manifestPath: string, kind: "gradle" | "maven"): string[] {
  let content: string;
  try {
    content = fs.readFileSync(manifestPath, "utf-8");
  } catch {
    return [];
  }

  const urls = new Set<string>();
  if (kind === "gradle") {
    // url 'https://...' / url "..." / url uri("...") / url = uri("...") — covers maven { url ... } blocks
    for (const m of content.matchAll(/url\s*(?:=\s*)?(?:uri\(\s*)?["'](https?:\/\/[^"']+)["']/g)) {
      urls.add(m[1]!);
    }
    if (/mavenCentral\s*\(/.test(content)) urls.add(MAVEN_CENTRAL);
    if (/jcenter\s*\(/.test(content)) urls.add("https://jcenter.bintray.com");
    if (/\bgoogle\s*\(/.test(content)) urls.add("https://dl.google.com/dl/android/maven2");
  } else {
    collectMavenRepoUrls(content, urls);
  }

  return [...urls];
}

/** Collect <url> entries from a Maven <repositories> block. */
function collectMavenRepoUrls(content: string, urls: Set<string>): void {
  const repos = /<repositories>[\s\S]*?<\/repositories>/.exec(content);
  if (repos) {
    for (const m of repos[0].matchAll(/<url>([^<]+)<\/url>/g)) urls.add(m[1]!.trim());
  }
  if (urls.size === 0) urls.add(MAVEN_CENTRAL); // Maven always has central implicitly
}

/** True when `version` appears exactly in the <versions> list of a maven-metadata.xml body. Null when the body has no <versions> element. Pure — unit-testable. */
export function versionInMetadata(xml: string, version: string): boolean | null {
  const versions = /<versions>([\s\S]*?)<\/versions>/.exec(xml);
  if (!versions) return null;
  for (const m of versions[0].matchAll(/<version>([^<]+)<\/version>/g)) {
    if (m[1]!.trim() === version) return true;
  }
  return false;
}

/** Smallest non-SNAPSHOT version strictly greater than `minVersion`, or null. Pure — unit-testable. */
export function pickNextVersion(versions: string[], minVersion: string): string | null {
  const above = versions.filter(v => !/\.?snapshot$/i.test(v) && compareMavenVersion(v, minVersion) > 0);
  if (above.length === 0) return null;
  above.sort(compareMavenVersion);
  return above[0]!;
}

/** Version entries of a Maven maven-metadata.xml, in document order. */
export function extractMetadataVersions(body: string): string[] {
  const versions = [...body.matchAll(/<version>([^<]+)<\/version>/g)].map(m => m[1].trim());
  const latest = /<latest>([^<]+)<\/latest>/.exec(body);
  if (latest) {
    const v = latest[1].trim();
    if (!versions.includes(v)) versions.push(v);
  }
  return versions;
}

/** True for pre-release / snapshot version strings (Maven convention). */
function isPreReleaseOrSnapshot(version: string): boolean {
  return /SNAPSHOT$/i.test(version) ||
    /-(alpha|beta|rc|cr|milestone|ea|dev)(\d*)$|-m\d+$/i.test(version);
}

/** The qualifier after the last dash, e.g. "jre" in "33.6.0-jre". */
function qualifierSuffix(version: string): string {
  const idx = version.lastIndexOf("-");
  return idx > 0 ? version.slice(idx + 1) : "";
}

/**
 * Newest non-prerelease Maven release strictly newer than `currentVersion`
 * (Maven version ordering), or null when the newest available is not newer
 * (or there are no versions). Ties on numeric equality (e.g. 33.7.2-jre vs
 * 33.7.2-android) prefer the release carrying the same qualifier suffix as
 * `currentVersion`, else the first in document order — so a -jre line stays
 * on -jre when the vendor publishes both variants of the same number.
 */
export function latestReleaseVersion(versions: string[], currentVersion: string): string | null {
  const eligible = versions.filter(v => !isPreReleaseOrSnapshot(v) && compareMavenVersion(v, currentVersion) > 0);
  if (eligible.length === 0) return null;
  let best = eligible[0];
  for (const v of eligible.slice(1)) {
    const cmp = compareMavenVersion(v, best);
    if (cmp > 0) best = v;
    else if (cmp === 0) {
      // Numeric tie: prefer the one matching the current qualifier suffix.
      const curSuffix = qualifierSuffix(currentVersion);
      if (curSuffix && qualifierSuffix(v) === curSuffix && qualifierSuffix(best) !== curSuffix) best = v;
    }
  }
  return best;
}

/**
 * True when Basic auth from the environment should be sent to this host.
 * A label must be exactly `artifactory` or the host must be `*.jfrog.io`.
 * `notartifactory.example` does not qualify.
 */
export function hostAcceptsEnvCredentials(host: string): boolean {
  const labels = host.toLowerCase().split(".");
  if (labels.at(-1) === "io" && labels.at(-2) === "jfrog") return true;
  return labels.includes("artifactory");
}

export interface RepoRequestInit {
  headers: Record<string, string>;
  /** `manual` when a password is attached, so a redirect cannot carry it. */
  redirect: "follow" | "manual";
}

/** Headers for a repository metadata GET. Passwords go only to https, and never on a redirect. */
export function repoRequestInit(url: string, creds?: { user?: string; pass?: string }): RepoRequestInit | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;

  const headers: Record<string, string> = {};
  const user = creds?.user;
  const pass = creds?.pass;
  if (parsed.protocol === "https:" && user && pass && hostAcceptsEnvCredentials(parsed.hostname)) {
    const basicAuth = Buffer.from(`${user}:${pass}`).toString("base64");
    headers.Authorization = `Basic ${basicAuth}`;
    return { headers, redirect: "manual" };
  }
  return { headers, redirect: "follow" };
}

/** Fetch a document with a short timeout and optional env-based Basic auth. Null on any failure. */
async function fetchText(url: string): Promise<string | null> {
  const init = repoRequestInit(url, {
    user: process.env.JFROG_USER || process.env.MAVEN_USERNAME,
    pass: process.env.JFROG_TOKEN || process.env.MAVEN_PASSWORD,
  });
  if (!init) return null;

  try {
    const res = await fetch(url, { headers: init.headers, signal: AbortSignal.timeout(10_000), redirect: init.redirect });
    if (init.redirect === "manual" && res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return null;
      const next = new URL(loc, url);
      if (next.protocol !== "https:") return null;
      const again = await fetch(next, { signal: AbortSignal.timeout(10_000), redirect: "manual" });
      if (!again.ok) return null;
      return await again.text();
    }
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

/** Remove trailing slashes (linear scan, no regex). */
function stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "/") end--;
  return s.slice(0, end);
}

/**
 * Smallest version available in the project's repositories that is strictly greater
 * than `minVersion`, or null when none exists or metadata cannot be fetched
 * (offline, auth failure, unknown layout). Best-effort.
 */
export async function findNextAvailableVersion(
  manifestPath: string,
  kind: "gradle" | "maven",
  packageName: string,
  minVersion: string,
): Promise<string | null> {
  const [group, name] = packageName.split(":");
  if (!group || !name) return null;

  const baseUrls = extractRepoUrls(manifestPath, kind);
  if (baseUrls.length === 0) return null;

  const groupPath = group.replaceAll(".", "/");
  const seen = new Set<string>();
  for (const base of baseUrls) {
    const url = `${stripTrailingSlashes(base)}/${groupPath}/${name}/maven-metadata.xml`;
    const xml = await fetchText(url);
    if (!xml) continue;
    for (const m of xml.matchAll(/<version>([^<]+)<\/version>/g)) {
      seen.add(m[1]!.trim());
    }
  }

  return pickNextVersion([...seen], minVersion);
}

/**
 * Latest non-prerelease release of `packageName` strictly newer than
 * `currentVersion`, read from the repository's maven-metadata.xml (the project's
 * declared repositories first, then Maven Central). `version` is null when nothing
 * newer exists or no metadata was reachable; `metadataFound` distinguishes "already
 * at the latest release" from "no metadata could be fetched".
 */
export async function findLatestAvailableVersion(
  manifestPath: string,
  kind: "gradle" | "maven",
  packageName: string,
  currentVersion: string,
): Promise<{ version: string | null; metadataFound: boolean }> {
  const [group, artifact] = packageName.split(":");
  if (!group || !artifact) return { version: null, metadataFound: false };

  let bases = extractRepoUrls(manifestPath, kind);
  if (!bases.some(b => stripTrailingSlashes(b) === MAVEN_CENTRAL)) bases.push(MAVEN_CENTRAL);
  const groupPath = group.replaceAll(".", "/");
  for (const base of bases) {
    const xml = await fetchText(`${stripTrailingSlashes(base)}/${groupPath}/${artifact}/maven-metadata.xml`);
    if (!xml) continue;
    const versions = extractMetadataVersions(xml);
    if (versions.length === 0) continue;
    return { version: latestReleaseVersion(versions, currentVersion), metadataFound: true };
  }
  return { version: null, metadataFound: false };
}

/**
 * Whether `version` is listed in the maven-metadata.xml of any of the project's repositories.
 * True when a repository lists it; false when metadata was fetched but no repository lists
 * the version (e.g. an advisory "fixed" version that was never published); null when no
 * metadata could be fetched at all (offline, auth failure) — callers keep best-effort behavior.
 */
export async function versionPublishedInRepos(
  manifestPath: string,
  kind: "gradle" | "maven",
  packageName: string,
  version: string,
): Promise<boolean | null> {
  const [group, name] = packageName.split(":");
  if (!group || !name) return null;

  const baseUrls = extractRepoUrls(manifestPath, kind);
  if (baseUrls.length === 0) return null;

  const groupPath = group.replaceAll(".", "/");
  let fetchedAny = false;
  for (const base of baseUrls) {
    const url = `${stripTrailingSlashes(base)}/${groupPath}/${name}/maven-metadata.xml`;
    const xml = await fetchText(url);
    if (!xml) continue;
    fetchedAny = true;
    if (versionInMetadata(xml, version)) return true;
  }
  return fetchedAny ? false : null;
}
