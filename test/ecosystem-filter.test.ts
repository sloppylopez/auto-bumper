import { filterPackagesByEcosystem, scanEcosystemFilterForKind } from "../src/lib/ecosystem-filter.ts";
import type { PackageRef } from "../src/lib/types.ts";

const gradlePkg = (name: string): PackageRef => ({
  ecosystem: "maven",
  name,
  version: "1.0.0",
  manifestPath: "/proj/build.gradle",
});

const pomPkg = (name: string): PackageRef => ({
  ecosystem: "maven",
  name,
  version: "1.0.0",
  manifestPath: "/proj/pom.xml",
});

describe("filterPackagesByEcosystem", () => {
  const packages = [
    gradlePkg("com.example:from-gradle"),
    pomPkg("com.example:from-pom"),
    { ecosystem: "npm", name: "lodash", version: "4.0.0", manifestPath: "package-lock.json" },
  ];

  it("gradle filter keeps build.gradle manifest packages", () => {
    const out = filterPackagesByEcosystem(packages, "gradle");
    expect(out).toHaveLength(1);
    expect(out[0].name).toBe("com.example:from-gradle");
  });

  it("maven filter keeps pom packages, excludes build.gradle", () => {
    const out = filterPackagesByEcosystem(packages, "maven");
    expect(out.map(p => p.name)).toContain("com.example:from-pom");
    expect(out.map(p => p.name)).not.toContain("com.example:from-gradle");
  });

  it("scanEcosystemFilterForKind maps gradle to gradle not maven", () => {
    expect(scanEcosystemFilterForKind("gradle")).toBe("gradle");
    expect(scanEcosystemFilterForKind("maven")).toBe("maven");
    expect(scanEcosystemFilterForKind("npm")).toBe("npm");
  });
});
