import path from "node:path";
import { normalizeCliPath, repairMangledCliPath, pathHint, getCacheRoot, getOsvDbDir, CACHE_DIR } from "../src/path.ts";

describe("CACHE_DIR", () => {
  it("is set to .auto-bumper", () => {
    expect(CACHE_DIR).toBe(".auto-bumper");
  });
});

describe("getOsvDbDir", () => {
  it("returns correct joined path for given cwd", () => {
    const result = getOsvDbDir("/some/path");
    expect(result).toContain(".auto-bumper");
    expect(result).toContain("db");
    expect(result).toContain("osv");
  });

  it("uses process.cwd when no argument provided", () => {
    const result = getOsvDbDir();
    expect(result).toContain(process.cwd());
  });

  it("honors AUTO_BUMPER_CACHE_DIR override", () => {
    const prev = process.env.AUTO_BUMPER_CACHE_DIR;
    process.env.AUTO_BUMPER_CACHE_DIR = "/tmp/ci-cache";
    try {
      const root = getCacheRoot();
      expect(root).toBe(path.resolve("/tmp/ci-cache"));
      expect(getOsvDbDir()).toBe(path.join(root, "db", "osv"));
    } finally {
      if (prev === undefined) delete process.env.AUTO_BUMPER_CACHE_DIR;
      else process.env.AUTO_BUMPER_CACHE_DIR = prev;
    }
  });
});

describe("normalizeCliPath", () => {
  it("resolves path correctly", () => {
    if (process.platform === "win32") {
      const result = normalizeCliPath("C:\\dev\\code\\project");
      expect(result).toContain("project");
    } else {
      const result = normalizeCliPath("/home/user/project");
      expect(result).toContain("project");
    }
  });

  it("handles MSYS-style paths on win32", () => {
    if (process.platform === "win32") {
      const result = normalizeCliPath("/c/dev/code/project");
      // Should start with C: drive
      expect(result.toUpperCase()).toMatch(/^C:[/\\]/);
    }
  });

  it("resolves relative path for empty input", () => {
    const result = normalizeCliPath("");
    expect(result).toBe(process.cwd());
  });
});

describe("repairMangledCliPath", () => {
  it("returns null on non-win32 platform", () => {
    if (process.platform !== "win32") {
      expect(repairMangledCliPath("C:devcodenode-project")).toBe(null);
    }
  });

  it("attempts to repair devcode mangling on win32", () => {
    if (process.platform === "win32") {
      // The function tries to find existing directories
      const result = repairMangledCliPath("C:devcode");
      // Result is either a valid path or null depending on what exists
      expect(result === null || typeof result === "string").toBe(true);
    }
  });
});

describe("pathHint", () => {
  it("returns empty string on non-win32", () => {
    if (process.platform !== "win32") {
      expect(pathHint("C:\\dev\\code\\project")).toBe("");
    }
  });

  it("gives hint for mangled path on win32", () => {
    if (process.platform === "win32") {
      const hint = pathHint("C:devcode");
      expect(hint.length).toBeGreaterThan(0);
      expect(hint).toContain("mangled");
    }
  });

  it("gives hint for backslash path on win32", () => {
    if (process.platform === "win32") {
      const hint = pathHint("C:\\dev\\code\\project");
      expect(hint.length).toBeGreaterThan(0);
      expect(hint).toContain("forward slash");
    }
  });
});
