import { describe, it, expect } from "bun:test";
import { parseMavenTree } from "../src/lib/parse-lockfile.ts";

describe("parseMavenTree", () => {
  it("retains parent edges and skips omitted-for-duplicate lines", () => {
    const tree = [
      "[INFO] --- maven-dependency-plugin:3.6.1:tree (default-cli) @ sample-app ---",
      "[INFO] com.example:sample-app:jar:0.0.1-SNAPSHOT",
      "[INFO] +- org.a:a:jar:1.0.0:compile",
      "[INFO] |  \\- org.b:b:jar:2.0.0:compile",
      "[INFO] |     \\- org.d:d:jar:1.0.0:compile",
      "[INFO] \\- org.c:c:jar:3.0.0:compile",
      "[INFO]    \\- org.b:b:jar:2.0.0:compile (omitted for duplicate)",
    ].join("\n");
    const result = parseMavenTree(tree, "pom.xml");
    expect(result.packages.map(p => p.name)).toEqual([
      "com.example:sample-app",
      "org.a:a",
      "org.b:b",
      "org.d:d",
      "org.c:c",
    ]);
    // Root project line has no parent.
    expect(result.packages.find(p => p.name === "com.example:sample-app")?.requiredBy).toBeUndefined();
    expect(result.packages.find(p => p.name === "org.a:a")?.requiredBy).toEqual(["com.example:sample-app"]);
    expect(result.packages.find(p => p.name === "org.c:c")?.requiredBy).toEqual(["com.example:sample-app"]);
    expect(result.packages.find(p => p.name === "org.b:b")?.requiredBy).toEqual(["org.a:a"]);
    expect(result.packages.find(p => p.name === "org.d:d")?.requiredBy).toEqual(["org.b:b"]);
  });

  it("keeps packages without tree prefixes free of requiredBy", () => {
    const result = parseMavenTree("[INFO] com.example:plain:jar:1.0.0\n", "pom.xml");
    expect(result.packages.find(p => p.name === "com.example:plain")?.requiredBy).toBeUndefined();
  });

  it("keeps parent edges for nodes drawn under a last-child branch (space-indented)", () => {
    // Regression: stripping the indentation after "[INFO]" collapsed space-indented children
    // (e.g. everything under a project's last direct dependency) into the project root.
    const tree = [
      "[INFO] com.example:sample-app:jar:0.0.1-SNAPSHOT",
      "[INFO] \\- org.wiremock:wiremock:jar:3.10.0:test",
      "[INFO]    +- org.eclipse.jetty:jetty-server:jar:12.0.39:test",
      "[INFO]    |  \\- org.eclipse.jetty:jetty-http:jar:12.0.39:test",
      "[INFO]    +- org.eclipse.jetty:jetty-servlet:jar:11.0.24:test",
    ].join("\n");
    const result = parseMavenTree(tree, "pom.xml");
    expect(result.packages.find(p => p.name === "org.wiremock:wiremock")?.requiredBy).toEqual(["com.example:sample-app"]);
    expect(result.packages.find(p => p.name === "org.eclipse.jetty:jetty-server")?.requiredBy).toEqual(["org.wiremock:wiremock"]);
    expect(result.packages.find(p => p.name === "org.eclipse.jetty:jetty-http")?.requiredBy).toEqual(["org.eclipse.jetty:jetty-server"]);
    expect(result.packages.find(p => p.name === "org.eclipse.jetty:jetty-servlet")?.requiredBy).toEqual(["org.wiremock:wiremock"]);
  });
});
