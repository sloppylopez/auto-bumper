/** Normalized bump-apply result shared by all manifest editors. */
export interface BumpApplyResult {
  /** Packages rewritten directly in the manifest (or "name: detail" change labels). */
  bumped: string[];
  /** Packages applied via a managed constraint/pin block — written to disk, not direct rewrites. */
  constrained: string[];
  /** Packages NOT applied (excluded, or no applicable version entry found). */
  missed: string[];
  warnings: string[];
}

/** How a single bump request was applied to the manifest. */
export type BumpApplyMethod = "direct" | "constrained" | "missed" | "unknown";

/** Raw shapes returned by the per-ecosystem editors (see *-editor.ts ApplyResult). */
type RawBumpApplyResult =
  | { direct: string[]; constrained?: string[]; excluded?: string[]; forced?: string[]; warnings: string[] }
  | { bumped: string[]; missed: string[]; warnings: string[] };

/**
 * Normalize an editor's raw apply result to the common shape.
 *
 * Gradle/Maven editors report `{direct, constrained, excluded}`; npm/cargo/python
 * report `{bumped, missed}`. Constrained bumps ARE applied (managed constraint
 * block written to disk) and must stay separate from `missed`/excluded packages,
 * otherwise the fix report undercounts file changes and omits them from the
 * Applied table.
 */
export function normalizeBumpApplyResult(result: RawBumpApplyResult): BumpApplyResult {
  if ("direct" in result) {
    return {
      bumped: [...result.direct],
      constrained: [...(result.constrained ?? [])],
      missed: [...(result.excluded ?? [])],
      warnings: result.warnings,
    };
  }
  return {
    bumped: [...result.bumped],
    constrained: [],
    missed: [...result.missed],
    warnings: result.warnings,
  };
}

/** True when an editor entry refers to the package (plain name or "name: detail" label). */
export function entryMatches(entries: string[] | undefined, packageName: string): boolean {
  if (!entries) return false;
  return entries.some(e => e === packageName || e.startsWith(`${packageName}:`));
}

/** Classify how a single package's bump was applied. */
export function bumpApplyMethod(result: BumpApplyResult, packageName: string): BumpApplyMethod {
  if (entryMatches(result.bumped, packageName)) return "direct";
  if (entryMatches(result.constrained, packageName)) return "constrained";
  if (result.missed.includes(packageName)) return "missed";
  return "unknown";
}
