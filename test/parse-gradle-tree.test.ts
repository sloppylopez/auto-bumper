import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseGradleTree } from "../src/lib/parse-lockfile.ts";

describe("parseGradleTree", () => {
  it("resolves arrow version resolution (->)", () => {
    const tree = "dependencies {\n+--- com.fasterxml.jackson.core:jackson-databind:2.21.5\n";
    const result = parseGradleTree(tree, "build.gradle");
    const jackson = result.packages.find((p) => p.name === "com.fasterxml.jackson.core:jackson-databind");
    expect(jackson).toBeDefined();
    expect(jackson?.version).toBe("2.21.5");
  });

  it("unwraps bare {strictly X} constraints and keeps the version (extension semantics)", () => {
    const tree = `+--- com.example:bom:{strictly 6.2.11}\n`;
    const result = parseGradleTree(tree, "build.gradle");
    const bom = result.packages.find((p) => p.name === "com.example:bom");
    expect(bom).toBeDefined();
    expect(bom?.version).toBe("6.2.11");
  });

  it("handles CRLF line endings with arrows and {strictly}", () => {
    const tree =
      "+--- org.springframework.boot:spring-boot-starter:3.4.0\r\n" +
      "|    \\--- com.example:bom:{strictly 6.2.11}\r\n" +
      "+--- com.fasterxml.jackson.core:jackson-databind:2.21.4 -> 2.21.5\r\n";
    const result = parseGradleTree(tree, "build.gradle");
    expect(result.packages.find((p) => p.name === "org.springframework.boot:spring-boot-starter")?.version).toBe("3.4.0");
    expect(result.packages.find((p) => p.name === "com.example:bom")?.version).toBe("6.2.11");
    expect(result.packages.find((p) => p.name === "com.fasterxml.jackson.core:jackson-databind")?.version).toBe("2.21.5");
  });

  it("strips parenthetical notes from versions", () => {
    const tree = `+--- com.example:lib:1.0.0 (constraint)\n`;
    const result = parseGradleTree(tree, "build.gradle");
    expect(result.packages.find((p) => p.name === "com.example:lib")?.version).toBe("1.0.0");
  });

  it("parses a real tree file from disk", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-bumper-tree-"));
    try {
      const file = path.join(dir, "tree.txt");
      fs.writeFileSync(file, "+--- com.fasterxml.jackson.core:jackson-databind:2.21.4 -> 2.21.5\n");
      const result = parseGradleTree(fs.readFileSync(file, "utf-8"), file);
      expect(result.packages.find((p) => p.name === "com.fasterxml.jackson.core:jackson-databind")?.version).toBe("2.21.5");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
