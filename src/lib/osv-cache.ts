/**
 * Shared gzip/json advisory cache under the OSV DB directory.
 * Atomic writes + corrupt-cache soft-fail (treat as miss).
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import type { AdvisoryEntry } from "./types.ts";
import { getOsvDbDir } from "../path.ts";

function parseCachePayload(jsonStr: string): AdvisoryEntry[] | null {
  try {
    const data = JSON.parse(jsonStr);
    if (!Array.isArray(data)) return null;
    return data as AdvisoryEntry[];
  } catch {
    return null;
  }
}

export function readCacheFile(osvName: string): AdvisoryEntry[] | null {
  const dir = getOsvDbDir();
  const gzPath = path.join(dir, `${osvName}.json.gz`);
  const jsonPath = path.join(dir, `${osvName}.json`);

  let raw: Buffer | string;
  if (fs.existsSync(gzPath) && fs.existsSync(jsonPath)) {
    // Prefer the newer file — a plain-JSON update must not be shadowed by a stale .gz.
    const useGz = fs.statSync(gzPath).mtimeMs >= fs.statSync(jsonPath).mtimeMs;
    raw = useGz ? fs.readFileSync(gzPath) : fs.readFileSync(jsonPath, "utf-8");
  } else if (fs.existsSync(gzPath)) {
    raw = fs.readFileSync(gzPath);
  } else if (fs.existsSync(jsonPath)) {
    raw = fs.readFileSync(jsonPath, "utf-8");
  } else {
    return null;
  }

  try {
    const jsonStr = typeof raw === "string" ? raw : zlib.gunzipSync(raw).toString();
    return parseCachePayload(jsonStr);
  } catch {
    return null;
  }
}

/** Atomic replace: write temp beside dest, then rename (Windows-safe). */
function atomicWriteFile(destPath: string, data: Buffer | string): void {
  const tmp = `${destPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, data);
  try {
    fs.renameSync(tmp, destPath);
  } catch {
    try {
      if (fs.existsSync(destPath)) fs.unlinkSync(destPath);
      fs.renameSync(tmp, destPath);
    } catch (err) {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // best effort
      }
      throw err;
    }
  }
}

export function writeCacheFile(osvName: string, data: AdvisoryEntry[]): void {
  const dir = getOsvDbDir();
  const gzPath = path.join(dir, `${osvName}.json.gz`);
  const jsonPath = path.join(dir, `${osvName}.json`);
  const jsonStr = JSON.stringify(data, null, 0);
  // Round-trip validate before committing to disk.
  if (parseCachePayload(jsonStr) === null) {
    throw new Error(`Refusing to cache non-array advisory payload for ${osvName}`);
  }
  const compressed = zlib.gzipSync(jsonStr);
  fs.mkdirSync(dir, { recursive: true });
  atomicWriteFile(gzPath, compressed);
  if (fs.existsSync(jsonPath)) fs.unlinkSync(jsonPath);
}

/** Age of cache file in ms (newest of .gz/.json), or null if missing. */
export function getCacheAgeMs(osvName: string): number | null {
  const dir = getOsvDbDir();
  const gzPath = path.join(dir, `${osvName}.json.gz`);
  const jsonPath = path.join(dir, `${osvName}.json`);
  let latest = 0;
  for (const p of [gzPath, jsonPath]) {
    if (fs.existsSync(p)) latest = Math.max(latest, fs.statSync(p).mtimeMs);
  }
  return latest === 0 ? null : Date.now() - latest;
}

/** Read the ETag recorded alongside a cached dump, or null when absent. */
export function readCacheEtag(osvName: string): string | null {
  const p = path.join(getOsvDbDir(), `${osvName}.etag`);
  try {
    const v = fs.readFileSync(p, "utf8").trim();
    return v.length > 0 ? v : null;
  } catch {
    return null;
  }
}

/** Record the ETag of the cached dump for future freshness probes. */
export function writeCacheEtag(osvName: string, etag: string): void {
  const dir = getOsvDbDir();
  fs.mkdirSync(dir, { recursive: true });
  atomicWriteFile(path.join(dir, `${osvName}.etag`), etag);
}

/** Remove cached advisory files for an ecosystem (force refresh). */
export function deleteCacheFile(osvName: string): void {
  const dir = getOsvDbDir();
  for (const ext of [".json.gz", ".json", ".etag"]) {
    const p = path.join(dir, `${osvName}${ext}`);
    try {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch {
      // best effort
    }
  }
}
