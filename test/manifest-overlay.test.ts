import {
  overlayManifestDirectDeps,
  readNpmManifestDirectDeps,
  fixLoopBlockedMessage,
} from "../src/lib/manifest-overlay.ts";
import { fixLoopStopReason } from "../src/lib/fix-loop.ts";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

describe("overlayManifestDirectDeps", () => {
  it("overrides lockfile version with package.json direct dep", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-overlay-"));
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ dependencies: { lodash: "^4.17.21" } }),
      "utf-8",
    );

    try {
      const packages = [{
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.20",
        manifestPath: "package-lock.json",
      }];
      const result = overlayManifestDirectDeps(packages, dir);
      expect(result.packages[0].version).toBe("4.17.21");
      expect(result.overlaid.length).toBe(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("overrides Cargo.lock with Cargo.toml direct dep", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-cargo-"));
    fs.writeFileSync(
      path.join(dir, "Cargo.toml"),
      '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1.35.0"\n',
      "utf-8",
    );

    try {
      const packages = [{
        ecosystem: "crates.io",
        name: "tokio",
        version: "1.34.0",
        manifestPath: "Cargo.lock",
      }];
      const result = overlayManifestDirectDeps(packages, dir);
      expect(result.packages[0].version).toBe("1.35.0");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("readNpmManifestDirectDeps", () => {
  it("reads dependencies and devDependencies", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-npm-"));
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({
        dependencies: { a: "^1.0.0" },
        devDependencies: { b: "~2.0.0" },
      }),
      "utf-8",
    );
    try {
      const deps = readNpmManifestDirectDeps(path.join(dir, "package.json"));
      expect(deps.get("a")).toBe("1.0.0");
      expect(deps.get("b")).toBe("2.0.0");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("fixLoopBlockedMessage", () => {
  it("mentions allow flags", () => {
    const msg = fixLoopBlockedMessage({
      findingCount: 2,
      skippedMajors: 1,
      skippedRenames: 1,
    });
    expect(msg).toContain("--allow-major");
    expect(msg).toContain("--allow-renames");
  });
});

describe("fixLoopStopReason planSig", () => {
  it("stalls when same plan signature repeats", () => {
    expect(fixLoopStopReason({
      findingCount: 2,
      findingSig: "a@1:GHSA-1",
      prevFindingSig: "a@1:GHSA-1",
      iteration: 3,
      maxIterations: 10,
      lastAppliedCount: 1,
      planSig: "b:pkg@2.0",
      prevPlanSig: "b:pkg@2.0",
    })).toBe("stall");
  });
});
