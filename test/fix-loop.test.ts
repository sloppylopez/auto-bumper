import {
  findingSignature,
  fixLoopStopReason,
  fixLoopStopMessage,
} from "../src/lib/fix-loop.ts";

const f = (packageName: string, installedVersion: string, id = "GHSA-1") => ({
  packageName,
  installedVersion,
  id,
});

describe("findingSignature", () => {
  it("orders findings stably", () => {
    const sig = findingSignature([
      f("b:lib", "2.0"),
      f("a:lib", "1.0"),
    ]);
    expect(sig).toBe("a:lib@1.0:GHSA-1|b:lib@2.0:GHSA-1");
  });
});

describe("fixLoopStopReason", () => {
  const base = {
    findingCount: 2,
    findingSig: "a@1:GHSA-1|b@2:GHSA-2",
    prevFindingSig: "x@1:GHSA-0",
    iteration: 2,
    maxIterations: 10,
    lastAppliedCount: 1,
  };

  it("returns clean when no findings", () => {
    expect(fixLoopStopReason({ ...base, findingCount: 0 })).toBe("clean");
  });

  it("returns cap at max iterations", () => {
    expect(fixLoopStopReason({ ...base, iteration: 10, maxIterations: 10 })).toBe("cap");
  });

  it("returns stall when signature unchanged and nothing applied", () => {
    expect(fixLoopStopReason({
      ...base,
      findingSig: "same@1:GHSA-1",
      prevFindingSig: "same@1:GHSA-1",
      lastAppliedCount: 0,
    })).toBe("stall");
  });

  it("continues when findings increased but last pass applied fixes", () => {
    expect(fixLoopStopReason({
      ...base,
      findingCount: 3,
      findingSig: "a@1:GHSA-1|b@2:GHSA-2|c@3:GHSA-3",
      prevFindingSig: "a@1:GHSA-1",
      lastAppliedCount: 1,
    })).toBeNull();
  });

  it("continues on first iteration even with zero prior applies", () => {
    expect(fixLoopStopReason({
      ...base,
      iteration: 1,
      prevFindingSig: null,
      lastAppliedCount: 0,
    })).toBeNull();
  });

  it("returns oscillation when count repeats after different counts", () => {
    expect(fixLoopStopReason({
      ...base,
      findingCount: 1,
      findingCountHistory: [6, 1, 7, 1],
      lastAppliedCount: 2,
    })).toBe("oscillation");
  });

  it("returns stall when same plan signature repeats", () => {
    expect(fixLoopStopReason({
      ...base,
      planSig: "b:a@2",
      prevPlanSig: "b:a@2",
      lastAppliedCount: 1,
    })).toBe("stall");
  });
});

describe("fixLoopStopMessage", () => {
  it("formats stall and cap messages", () => {
    expect(fixLoopStopMessage("stall", { findingCount: 2, maxIterations: 10 }))
      .toContain("2 remaining");
    expect(fixLoopStopMessage("cap", { findingCount: 1, maxIterations: 5 }))
      .toContain("max iterations (5)");
  });
});
