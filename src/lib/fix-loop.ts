/**
 * Fix apply-loop control — when to keep re-scanning vs stop.
 */

export interface FindingSignatureInput {
  packageName: string;
  installedVersion: string;
  id: string;
}

/** Stable key for a vulnerable package instance in the resolved tree. */
export function findingSignature(findings: FindingSignatureInput[]): string {
  return findings
    .map(f => `${f.packageName}@${f.installedVersion}:${f.id}`)
    .sort((a, b) => a.localeCompare(b))
    .join("|");
}

export type FixLoopStopReason = "clean" | "stall" | "oscillation" | "cap" | null;

export interface FixLoopStopInput {
  findingCount: number;
  findingSig: string;
  prevFindingSig: string | null;
  iteration: number;
  maxIterations: number;
  lastAppliedCount: number;
  /** Same fix plan as previous iteration — pointless to re-apply. */
  planSig?: string | null;
  prevPlanSig?: string | null;
  /** Finding counts per iteration (for oscillation detection). */
  findingCountHistory?: number[];
}

/**
 * Whether the apply loop should exit before planning/applying again.
 * Returns null when the loop should continue.
 */
export function fixLoopStopReason(input: FixLoopStopInput): FixLoopStopReason {
  const {
    findingCount,
    findingSig,
    prevFindingSig,
    iteration,
    maxIterations,
    lastAppliedCount,
  } = input;

  if (findingCount === 0) return "clean";
  if (iteration >= maxIterations) return "cap";

  const {
    planSig,
    prevPlanSig,
    findingCountHistory,
  } = input;

  if (
    iteration > 1 &&
    planSig &&
    prevPlanSig &&
    planSig === prevPlanSig
  ) {
    return "stall";
  }

  if (
    iteration > 1 &&
    findingCountHistory &&
    findingCountHistory.length >= 2 &&
    lastAppliedCount > 0
  ) {
    const repeats = findingCountHistory.filter(c => c === findingCount).length;
    const hasDifferent = findingCountHistory.some(c => c !== findingCount);
    if (repeats >= 1 && hasDifferent) {
      return "oscillation";
    }
  }

  if (
    iteration > 1 &&
    prevFindingSig !== null &&
    findingSig === prevFindingSig &&
    lastAppliedCount === 0
  ) {
    return "stall";
  }
  return null;
}

export function fixLoopStopMessage(
  reason: Exclude<FixLoopStopReason, null>,
  opts: { findingCount: number; maxIterations: number },
): string {
  switch (reason) {
    case "clean":
      return "All vulnerabilities fixed.";
    case "stall":
      return `Stopped: same fixes repeating or no progress (${opts.findingCount} remaining).`;
    case "oscillation":
      return `Stopped: vulnerability count oscillating (${opts.findingCount} remaining) — mixed deps or constraints need manual review.`;
    case "cap":
      return `Stopped: reached max iterations (${opts.maxIterations}) with ${opts.findingCount} vulnerabilities remaining.`;
  }
}
