import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applySourceMigrations,
  describeSourceMigrations,
} from "../src/lib/source-migrations.ts";
import { sourceMigrationsForAppliedRenames } from "../src/lib/maven-renames.ts";

const JACKSON_RENAMES = [{
  packageName: "com.fasterxml.jackson.core:jackson-databind",
  renameTo: "tools.jackson.core:jackson-databind",
}];

describe("sourceMigrationsForAppliedRenames", () => {
  it("returns Jackson source config for tools.jackson rename", () => {
    const config = sourceMigrationsForAppliedRenames([{
      fromPackage: "com.fasterxml.jackson.core:jackson-databind",
      toPackage: "tools.jackson.core:jackson-databind",
    }]);
    expect(config).not.toBeNull();
    expect(config!.clusters).toContain("com.fasterxml.jackson.core|tools.jackson.core");
    expect(config!.java?.rules.length).toBeGreaterThan(0);
    expect(config!.java?.globs?.length).toBeGreaterThan(0);
  });

  it("returns null for unknown migration", () => {
    expect(sourceMigrationsForAppliedRenames([{
      fromPackage: "com.example:old-lib",
      toPackage: "com.example:new-lib",
    }])).toBeNull();
  });
});

describe("describeSourceMigrations", () => {
  it("describes Jackson cluster rules and globs", () => {
    const config = sourceMigrationsForAppliedRenames(JACKSON_RENAMES)!;
    const lines = describeSourceMigrations(config);
    expect(lines.some(l => l.includes("com.fasterxml.jackson.core|tools.jackson.core"))).toBe(true);
    expect(lines.some(l => l.includes("com.fasterxml.jackson -> tools.jackson"))).toBe(true);
    expect(lines.some(l => l.includes("src/main/java"))).toBe(true);
  });
});

describe("applySourceMigrations", () => {
  it("delegates to Java import rewriter", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-src-"));
    const javaDir = path.join(dir, "src", "main", "java", "com", "example");
    fs.mkdirSync(javaDir, { recursive: true });
    const filePath = path.join(javaDir, "App.java");
    fs.writeFileSync(
      filePath,
      "package com.example;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n",
      "utf-8",
    );

    try {
      const config = sourceMigrationsForAppliedRenames(JACKSON_RENAMES)!;
      const result = applySourceMigrations(dir, config);
      expect(result.changed.length).toBe(1);
      expect(result.byLanguage.java).toBe(1);
      expect(fs.readFileSync(filePath, "utf-8")).toContain("import tools.jackson.databind.ObjectMapper;");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
