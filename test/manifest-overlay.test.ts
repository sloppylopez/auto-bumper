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

  it("overlays optional, peer, and npm override versions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-npm-ov-"));
    fs.writeFileSync(path.join(dir, "package-lock.json"), "{}\n");
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({
        optionalDependencies: { debug: "4.3.4" },
        peerDependencies: { react: "18.3.1" },
        overrides: { minimist: "1.2.8" },
      }),
    );
    try {
      const packages = [
        { ecosystem: "npm", name: "debug", version: "4.3.0", manifestPath: "package-lock.json" },
        { ecosystem: "npm", name: "react", version: "18.2.0", manifestPath: "package-lock.json" },
        { ecosystem: "npm", name: "minimist", version: "1.2.5", manifestPath: "package-lock.json" },
      ];
      const result = overlayManifestDirectDeps(packages, dir);
      expect(result.packages.map(p => p.version)).toEqual(["4.3.4", "18.3.1", "1.2.8"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("overlays yarn resolutions and pnpm overrides from the matching lockfile", () => {
    const yarnDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-yarn-"));
    const pnpmDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-pnpm-"));
    fs.writeFileSync(path.join(yarnDir, "yarn.lock"), "");
    fs.writeFileSync(path.join(yarnDir, "package.json"), JSON.stringify({ resolutions: { lodash: "4.17.21" } }));
    fs.writeFileSync(path.join(pnpmDir, "pnpm-lock.yaml"), "");
    fs.writeFileSync(path.join(pnpmDir, "package.json"), JSON.stringify({ pnpm: { overrides: { lodash: "4.17.21" } } }));
    try {
      const locked = [{ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "lock" }];
      expect(overlayManifestDirectDeps(locked, yarnDir).packages[0].version).toBe("4.17.21");
      expect(overlayManifestDirectDeps(locked, pnpmDir).packages[0].version).toBe("4.17.21");
    } finally {
      fs.rmSync(yarnDir, { recursive: true, force: true });
      fs.rmSync(pnpmDir, { recursive: true, force: true });
    }
  });

  it("overlays poetry.lock and requirements.txt direct versions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-py-"));
    fs.writeFileSync(
      path.join(dir, "pyproject.toml"),
      "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \">=2.32.0\"\n",
    );
    fs.writeFileSync(path.join(dir, "requirements.txt"), "typing_extensions==4.12.2\nflask<=2.0.0\n");
    try {
      const packages = [
        { ecosystem: "pypi", name: "requests", version: "2.31.0", manifestPath: "poetry.lock" },
        { ecosystem: "pypi", name: "typing-extensions", version: "4.9.0", manifestPath: "poetry.lock" },
        { ecosystem: "pypi", name: "flask", version: "1.9.0", manifestPath: "poetry.lock" },
      ];
      const result = overlayManifestDirectDeps(packages, dir);
      expect(result.packages[0].version).toBe("2.32.0");
      expect(result.packages[1].version).toBe("4.12.2");
      expect(result.packages[2].version).toBe("1.9.0");
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
