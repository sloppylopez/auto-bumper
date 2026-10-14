import { describe, expect, it } from "bun:test";
import { gradleScanScopeNote } from "../src/scan.ts";
import type { PackageRef } from "../src/lib/types.ts";

const runtime = ["runtimeClasspath"] as const;

function pkg(manifestPath: string): PackageRef {
  return { ecosystem: "maven", name: "org.example:lib", version: "1.0", manifestPath };
}

describe("gradleScanScopeNote", () => {
  it("does not label a Maven pom scan as Gradle", () => {
    expect(gradleScanScopeNote([pkg("C:/dev/code/my-app/pom.xml")], runtime)).toBe("");
  });

  it("labels a Gradle manifest scan with the configurations that were resolved", () => {
    expect(gradleScanScopeNote([pkg("app/build.gradle")], runtime)).toBe(" (Gradle runtimeClasspath)");
    expect(gradleScanScopeNote([pkg("app/build.gradle.kts")], runtime)).toBe(" (Gradle runtimeClasspath)");
  });

  it("stays empty when no Gradle configuration filter was requested", () => {
    expect(gradleScanScopeNote([pkg("app/build.gradle")])).toBe("");
  });
});
