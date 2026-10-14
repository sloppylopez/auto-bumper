import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyJavaImportMigrations,
  rewriteJavaImportTarget,
  rewriteJavaImports,
  rewriteJavaPackage,
} from "../src/lib/java-import-editor.ts";
import { sourceMigrationsForAppliedRenames } from "../src/lib/maven-renames.ts";

const JACKSON_RULES = sourceMigrationsForAppliedRenames([{
  packageName: "com.fasterxml.jackson.core:jackson-databind",
  renameTo: "tools.jackson.core:jackson-databind",
}])!.java!.rules;

describe("rewriteJavaPackage", () => {
  it("rewrites databind package prefix", () => {
    expect(rewriteJavaPackage("com.fasterxml.jackson.databind", JACKSON_RULES))
      .toBe("tools.jackson.databind");
  });

  it("keeps com.fasterxml.jackson.annotation", () => {
    expect(rewriteJavaPackage("com.fasterxml.jackson.annotation", JACKSON_RULES))
      .toBe("com.fasterxml.jackson.annotation");
  });

  it("rewrites jsr310 datatype to jackson 3 ext package", () => {
    expect(rewriteJavaPackage("com.fasterxml.jackson.datatype.jsr310", JACKSON_RULES))
      .toBe("tools.jackson.databind.ext.javatime");
  });
});

describe("rewriteJavaImports", () => {
  it("rewrites ObjectMapper import", () => {
    const src = "import com.fasterxml.jackson.databind.ObjectMapper;\n";
    const { content, changed } = rewriteJavaImports(src, JACKSON_RULES);
    expect(changed).toBe(true);
    expect(content).toContain("import tools.jackson.databind.ObjectMapper;");
    expect(content).not.toContain("com.fasterxml.jackson.databind");
  });

  it("keeps JsonProperty annotation import", () => {
    const src = "import com.fasterxml.jackson.annotation.JsonProperty;\n";
    const { content, changed } = rewriteJavaImports(src, JACKSON_RULES);
    expect(changed).toBe(false);
    expect(content).toContain("com.fasterxml.jackson.annotation.JsonProperty");
  });

  it("leaves unrelated imports unchanged", () => {
    const src = "import java.util.List;\nimport org.springframework.stereotype.Service;\n";
    const { content, changed } = rewriteJavaImports(src, JACKSON_RULES);
    expect(changed).toBe(false);
    expect(content).toBe(src);
  });

  it("rewrites static imports", () => {
    const next = rewriteJavaImportTarget(
      "com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES",
      JACKSON_RULES,
    );
    expect(next).toBe(
      "tools.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES",
    );
  });
});

describe("applyJavaImportMigrations", () => {
  it("updates files under src/main/java", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-java-"));
    const javaDir = path.join(dir, "src", "main", "java", "com", "example");
    fs.mkdirSync(javaDir, { recursive: true });
    const filePath = path.join(javaDir, "App.java");
    fs.writeFileSync(
      filePath,
      "package com.example;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n",
      "utf-8",
    );

    try {
      const result = applyJavaImportMigrations(dir, JACKSON_RULES);
      expect(result.changed.length).toBe(1);
      const content = fs.readFileSync(filePath, "utf-8");
      expect(content).toContain("import tools.jackson.databind.ObjectMapper;");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("sourceMigrationsForAppliedRenames", () => {
  it("returns Jackson rules for tools.jackson rename", () => {
    const config = sourceMigrationsForAppliedRenames([{
      fromPackage: "com.fasterxml.jackson.core:jackson-databind",
      toPackage: "tools.jackson.core:jackson-databind",
    }]);
    expect(config).not.toBeNull();
    expect(config!.java!.rules.length).toBeGreaterThan(0);
    expect(config!.java!.globs!.length).toBeGreaterThan(0);
  });

  it("returns null for unknown migration", () => {
    const config = sourceMigrationsForAppliedRenames([{
      fromPackage: "com.example:old-lib",
      toPackage: "com.example:new-lib",
    }]);
    expect(config).toBeNull();
  });
});
