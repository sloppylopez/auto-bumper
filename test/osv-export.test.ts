import { describe, expect, it } from "bun:test";
import { osvDumpUrl, OSV_GCS_ECOSYSTEM } from "../src/lib/osv-export.ts";

describe("osvDumpUrl", () => {
  it("maps cache names to GCS ecosystem folders", () => {
    expect(OSV_GCS_ECOSYSTEM.Maven).toBe("Maven");
    expect(OSV_GCS_ECOSYSTEM.NPM).toBe("npm");
    expect(osvDumpUrl("Maven")).toBe("https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip");
    expect(osvDumpUrl("NPM")).toBe("https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip");
  });
});
