import { rewriteJsImports } from "../src/lib/js-import-editor.ts";
import { rewritePythonImports } from "../src/lib/python-import-editor.ts";
import { rewriteRustImports } from "../src/lib/rust-import-editor.ts";
import { detectEcosystemRenames } from "../src/lib/package-renames.ts";
import { sourceMigrationsForAppliedRenames } from "../src/lib/maven-renames.ts";
import type { AdvisoryEntry, Finding } from "../src/lib/types.ts";

describe("rewriteJsImports", () => {
  it("rewrites import from old package name", () => {
    const src = "import foo from 'old-pkg';\nconst x = require(\"old-pkg/lib\");\n";
    const { content, changed } = rewriteJsImports(src, [{ fromPackage: "old-pkg", toPackage: "new-pkg" }]);
    expect(changed).toBe(true);
    expect(content).toContain("from 'new-pkg'");
    expect(content).toContain('require("new-pkg/lib")');
  });
});

describe("rewritePythonImports", () => {
  it("rewrites import and from lines", () => {
    const src = "import old_pkg\nfrom old_pkg.utils import helper\n";
    const { content, changed } = rewritePythonImports(src, [{ fromPackage: "old-pkg", toPackage: "new-pkg" }]);
    expect(changed).toBe(true);
    expect(content).toContain("import new_pkg");
    expect(content).toContain("from new_pkg.utils import helper");
  });
});

describe("rewriteRustImports", () => {
  it("rewrites use statements", () => {
    const src = "use old_crate::io;\n";
    const { content, changed } = rewriteRustImports(src, [{ fromPackage: "old-crate", toPackage: "new-crate" }]);
    expect(changed).toBe(true);
    expect(content).toContain("use new_crate::io;");
  });
});

describe("detectEcosystemRenames", () => {
  const npmAdvisory: AdvisoryEntry = {
    id: "GHSA-npm-rename",
    aliases: [],
    ecosystems: ["npm"],
    summary: "test",
    severity: [],
    affected: [
      { package: { name: "old-pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] },
      { package: { name: "new-pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] },
    ],
    links: [],
  };

  const npmFinding: Finding = {
    id: "GHSA-npm-rename",
    aliases: [],
    ecosystem: "npm",
    packageName: "old-pkg",
    installedVersion: "1.0.0",
    vulnerableRange: ">=0",
    fixedVersions: [],
    severity: "HIGH",
    summary: "test",
    references: [],
  };

  it("detects npm package rename from OSV", () => {
    const renames = detectEcosystemRenames([npmFinding], [npmAdvisory], "npm");
    expect(renames).toHaveLength(1);
    expect(renames[0].toPackage).toBe("new-pkg");
  });
});

describe("sourceMigrationsForAppliedRenames ecosystems", () => {
  it("adds javascript rules for npm renames", () => {
    const config = sourceMigrationsForAppliedRenames([{
      packageName: "old-pkg",
      renameTo: "new-pkg",
      ecosystem: "npm",
    }]);
    expect(config?.javascript?.rules).toEqual([{ fromPackage: "old-pkg", toPackage: "new-pkg" }]);
  });

  it("adds python rules for pypi renames", () => {
    const config = sourceMigrationsForAppliedRenames([{
      packageName: "old-pkg",
      renameTo: "new-pkg",
      ecosystem: "pypi",
    }]);
    expect(config?.python?.rules).toEqual([{ fromPackage: "old-pkg", toPackage: "new-pkg" }]);
  });

  it("adds rust rules for crates.io renames", () => {
    const config = sourceMigrationsForAppliedRenames([{
      packageName: "old-crate",
      renameTo: "new-crate",
      ecosystem: "crates.io",
    }]);
    expect(config?.rust?.rules).toEqual([{ fromPackage: "old-crate", toPackage: "new-crate" }]);
  });
});
