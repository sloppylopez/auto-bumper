import {
  applyPolicyForRenames,
  isKeptCoordinate,
} from "../src/lib/maven-renames.ts";

describe("migration apply policy", () => {
  it("isKeptCoordinate recognizes cluster keepCoordinates", () => {
    expect(isKeptCoordinate("com.fasterxml.jackson.core:jackson-annotations")).toBe(true);
    expect(isKeptCoordinate("com.fasterxml.jackson.core:jackson-databind")).toBe(false);
  });

  it("applyPolicyForRenames merges Jackson cluster policy", () => {
    const policy = applyPolicyForRenames([
      {
        fromPackage: "com.fasterxml.jackson.core:jackson-databind",
        toPackage: "tools.jackson.core:jackson-databind",
      },
    ]);
    expect(policy.excludeOldCoordinates).toBe(true);
    expect(policy.keepCoordinates.has("com.fasterxml.jackson.core:jackson-annotations")).toBe(true);
    expect(policy.removeBomCoords).toContain("com.fasterxml.jackson:jackson-bom");
    expect(policy.rejectPins.has("tools.jackson.core:jackson-annotations")).toBe(true);
    expect(policy.extraPins.some(p => p.packageName === "com.fasterxml.jackson.core:jackson-annotations")).toBe(true);
  });

  it("applyPolicyForRenames is empty for unknown renames", () => {
    const policy = applyPolicyForRenames([
      { fromPackage: "com.example:old", toPackage: "com.example:new" },
    ]);
    expect(policy.excludeOldCoordinates).toBe(false);
    expect(policy.clusterKeys).toHaveLength(0);
  });
});
