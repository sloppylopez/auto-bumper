/**
 * Download per-ecosystem OSV vulnerability dumps from the public GCS bucket.
 * https://google.github.io/osv.dev/data/#per-ecosystem-downloads
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import type { AdvisoryEntry } from "./types.ts";
import { fetchWithRetry } from "./fetch-retry.ts";
import { enrichOsvVulnWithBridgedPackages } from "./osv-package-bridge.ts";

export const OSV_GCS_BASE = "https://storage.googleapis.com/osv-vulnerabilities";

/** Cache file osvName (NPM) -> GCS directory (npm). */
export const OSV_GCS_ECOSYSTEM: Record<string, string> = {
  NPM: "npm",
  "CRATES.IO": "crates.io",
  PyPI: "PyPI",
  Maven: "Maven",
};

export function osvDumpUrl(osvName: string): string {
  const gcsEco = OSV_GCS_ECOSYSTEM[osvName] || osvName;
  return `${OSV_GCS_BASE}/${gcsEco}/all.zip`;
}

/** ZIP local file header magic (PK\x03\x04). */
export function isZipBuffer(buf: Buffer): boolean {
  return buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
}

/** Minimum plausible OSV ecosystem dump size (empty zip is useless). */
export const OSV_ZIP_MIN_BYTES = 64;

/** Read ZIP central-directory names. Throws when the directory cannot be parsed. */
export function zipEntryNames(buf: Buffer): string[] {
  const eocdSig = 0x06054b50;
  let eocd = -1;
  const start = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= start; i--) {
    if (buf.readUInt32LE(i) === eocdSig) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("OSV zip missing central directory");
  const count = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || offset === 0xffffffff) {
    throw new Error("OSV zip uses ZIP64 and could not be checked for path traversal");
  }
  const names: string[] = [];
  for (let n = 0; n < count; n++) {
    if (offset + 46 > buf.length || buf.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error("OSV zip central directory is corrupt");
    }
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const nameStart = offset + 46;
    const name = buf.toString("utf8", nameStart, nameStart + nameLen);
    names.push(name);
    offset = nameStart + nameLen + extraLen + commentLen;
  }
  return names;
}

export function assertNoZipSlip(names: string[]): void {
  for (const name of names) {
    const normalized = name.replaceAll("\\", "/");
    if (
      !normalized
      || normalized.startsWith("/")
      || /^[A-Za-z]:/.test(normalized)
      || normalized.split("/").includes("..")
    ) {
      throw new Error(`OSV zip entry escapes extract dir: ${name}`);
    }
  }
}

function zipNamesOrTarList(buf: Buffer, zipPath: string): string[] {
  try {
    return zipEntryNames(buf);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes("ZIP64")) throw err;
  }
  const bins = process.platform === "win32"
    ? [String.raw`C:\Windows\System32\tar.exe`]
    : ["/usr/bin/tar"];
  for (const bin of bins) {
    if (!fs.existsSync(bin)) continue;
    const listed = spawnSync(bin, ["-tf", zipPath], { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });
    if (listed.status === 0 && listed.stdout) {
      return listed.stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    }
  }
  throw new Error("OSV zip is ZIP64 and no tar is available to check entry paths");
}

function extractZip(zipPath: string, destDir: string): void {
  const attempts: Array<{ bin: string; args: string[] }> = process.platform === "win32"
    ? [
        { bin: String.raw`C:\Windows\System32\tar.exe`, args: ["-xf", zipPath, "-C", destDir] },
        { bin: String.raw`C:\Program Files\Git\usr\bin\unzip.exe`, args: ["-oq", zipPath, "-d", destDir] },
        // PowerShell Expand-Archive — available without Git for Windows.
        {
          bin: String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
          args: [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            `Expand-Archive -LiteralPath '${zipPath.replaceAll("'", "''")}' -DestinationPath '${destDir.replaceAll("'", "''")}' -Force`,
          ],
        },
      ]
    : [
        { bin: "/usr/bin/tar", args: ["-xf", zipPath, "-C", destDir] },
        { bin: "/usr/bin/unzip", args: ["-oq", zipPath, "-d", destDir] },
      ];

  const errors: string[] = [];
  for (const { bin, args } of attempts) {
    if (!fs.existsSync(bin)) {
      errors.push(`${bin}: missing`);
      continue;
    }
    const result = spawnSync(bin, args, { encoding: "utf-8" });
    if (result.status === 0) return;
    const detail = result.stderr || result.stdout || `exit ${result.status}`;
    errors.push(`${bin}: ${detail}`);
  }

  throw new Error(`Failed to extract OSV zip: ${errors.join(" | ")}`);
}

export function mapOsvVulnToAdvisory(v: Record<string, unknown>): AdvisoryEntry {
  const vuln = enrichOsvVulnWithBridgedPackages(v);
  return {
    id: String(vuln.id),
    aliases: (vuln.aliases as string[]) ?? [],
    ecosystems: [
      ...new Set(
        ((vuln.affected as Array<{ package?: { ecosystem?: string } }>) || [])
          .map(a => a.package?.ecosystem)
          .filter((e): e is string => typeof e === "string"),
      ),
    ],
    summary: String(typeof vuln.summary === "string" ? vuln.summary : `${vuln.id} vulnerability`),
    severity: ((vuln.severity as Array<{ value?: string; score?: string }>) || []).map(s => ({
      type: "CVSS_V3_1",
      score: s.value || s.score || "3.0",
    })),
    affected: ((vuln.affected as Array<{ package?: object; versions?: string[]; ranges?: unknown[] }>) || []).map(a => ({
      package: a.package ?? {},
      versions: a.versions || [],
      ranges: a.ranges || [],
    })),
    links: ((vuln.references as Array<{ url: string }>) || []).map(r => ({ url: r.url })),
  };
}

/** Validate downloaded dump bytes before extract. */
export function assertValidOsvZip(buf: Buffer, opts: { contentLength?: number | null; url: string }): void {
  if (buf.length < OSV_ZIP_MIN_BYTES) {
    throw new Error(`OSV dump too small (${buf.length} bytes) from ${opts.url}`);
  }
  if (!isZipBuffer(buf)) {
    throw new Error(`OSV dump is not a ZIP (bad magic) from ${opts.url}`);
  }
  if (opts.contentLength != null && opts.contentLength > 0 && buf.length !== opts.contentLength) {
    throw new Error(
      `OSV dump size mismatch: got ${buf.length} bytes, Content-Length ${opts.contentLength} (${opts.url})`,
    );
  }
}
/** Download result: parsed advisories plus the remote object's ETag (for freshness probes). */
export interface OsvDumpResult {
  entries: AdvisoryEntry[];
  etag: string | null;
}

/** Download and parse all OSV records for an ecosystem. */
export async function downloadOsvEcosystemDump(osvName: string): Promise<OsvDumpResult> {
  const url = osvDumpUrl(osvName);
  const resp = await fetchWithRetry(url, undefined, { label: `OSV dump ${osvName}`, retries: 3 });
  if (!resp.ok) throw new Error(`OSV dump HTTP ${resp.status} (${url})`);
  const etag = resp.headers.get("etag") ?? resp.headers.get("last-modified");

  const contentLengthHeader = resp.headers.get("content-length");
  const contentLength = contentLengthHeader ? Number(contentLengthHeader) : null;
  const buf = Buffer.from(await resp.arrayBuffer());
  assertValidOsvZip(buf, { contentLength: Number.isFinite(contentLength) ? contentLength : null, url });

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-osv-"));
  const zipPath = path.join(tmpRoot, "all.zip");
  const extractDir = path.join(tmpRoot, "extract");

  try {
    fs.mkdirSync(extractDir, { recursive: true });
    fs.writeFileSync(zipPath, buf);
    assertNoZipSlip(zipNamesOrTarList(buf, zipPath));
    extractZip(zipPath, extractDir);

    const advisories: AdvisoryEntry[] = [];
    const walk = (dir: string) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          walk(full);
          continue;
        }
        if (!ent.name.endsWith(".json")) continue;
        const raw = JSON.parse(fs.readFileSync(full, "utf-8")) as Record<string, unknown>;
        advisories.push(mapOsvVulnToAdvisory(raw));
      }
    };
    walk(extractDir);

    if (advisories.length === 0) {
      throw new Error(`OSV dump extracted 0 advisories (${url}) — corrupt or unexpected layout`);
    }
    return { entries: advisories, etag };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

/** Per-process probe state: after one network failure, skip further HEAD checks (offline runs stay fast). */
let remoteProbeFailed = false;

/** Test seam: re-enable freshness probes after a simulated network failure. */
export function resetRemoteEtagProbe(): void {
  remoteProbeFailed = false;
}

/**
 * Cheap freshness probe: HEAD the ecosystem dump and return its ETag (Last-Modified as fallback).
 * Returns null when the remote state cannot be verified (network error, non-OK response).
 */
export async function checkRemoteEtag(osvName: string): Promise<string | null> {
  if (remoteProbeFailed) return null;
  try {
    const resp = await fetch(osvDumpUrl(osvName), { method: "HEAD", signal: AbortSignal.timeout(3000) });
    if (!resp.ok) {
      remoteProbeFailed = true;
      return null;
    }
    return resp.headers.get("etag") ?? resp.headers.get("last-modified");
  } catch {
    remoteProbeFailed = true;
    return null;
  }
}
