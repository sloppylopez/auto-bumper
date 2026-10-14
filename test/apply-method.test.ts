import {
  bumpApplyMethod,
  entryMatches,
  normalizeBumpApplyResult,
} from "../src/lib/apply-method.ts";

describe("normalizeBumpApplyResult", () => {
  it("keeps gradle constrained pins separate from excluded (regression: jsoup miscount)", () => {
    const result = normalizeBumpApplyResult({
      direct: ["org.apache.tomcat.embed:tomcat-embed-core"],
      constrained: ["org.jsoup:jsoup"],
      excluded: ["ch.qos.logback:logback-classic"],
      warnings: [],
    });
    expect(result.bumped).toEqual(["org.apache.tomcat.embed:tomcat-embed-core"]);
    expect(result.constrained).toEqual(["org.jsoup:jsoup"]);
    expect(result.missed).toEqual(["ch.qos.logback:logback-classic"]);
  });

  it("treats npm missed as not-applied, with no constrained bucket", () => {
    const result = normalizeBumpApplyResult({
      bumped: ["lodash"],
      missed: ["left-pad"],
      warnings: [],
    });
    expect(result.bumped).toEqual(["lodash"]);
    expect(result.constrained).toEqual([]);
    expect(result.missed).toEqual(["left-pad"]);
  });

  it("tolerates missing optional buckets", () => {
    const result = normalizeBumpApplyResult({ direct: [], warnings: [] });
    expect(result.constrained).toEqual([]);
    expect(result.missed).toEqual([]);
  });
});

describe("bumpApplyMethod", () => {
  const gradleResult = normalizeBumpApplyResult({
    direct: ["com.fasterxml.jackson.core:jackson-core"],
    constrained: ["org.jsoup:jsoup"],
    excluded: ["ch.qos.logback:logback-classic"],
    warnings: [],
  });

  it("classifies a direct rewrite", () => {
    expect(bumpApplyMethod(gradleResult, "com.fasterxml.jackson.core:jackson-core")).toBe("direct");
  });

  it("classifies a constraint pin as constrained, not missed (regression)", () => {
    expect(bumpApplyMethod(gradleResult, "org.jsoup:jsoup")).toBe("constrained");
  });

  it("classifies excluded packages as missed", () => {
    expect(bumpApplyMethod(gradleResult, "ch.qos.logback:logback-classic")).toBe("missed");
  });

  it("classifies unknown packages", () => {
    expect(bumpApplyMethod(gradleResult, "org.example:missing")).toBe("unknown");
  });
});

describe("entryMatches", () => {
  it("matches plain names and 'name: detail' labels", () => {
    expect(entryMatches(["lodash"], "lodash")).toBe(true);
    expect(entryMatches(["lodash: ^4.17.20 -> ^4.17.21"], "lodash")).toBe(true);
  });

  it("does not match a longer name sharing a prefix", () => {
    expect(entryMatches(["org.foo:bar-baz"], "org.foo:bar")).toBe(false);
  });

  it("returns false for undefined entries", () => {
    expect(entryMatches(undefined, "lodash")).toBe(false);
  });
});
