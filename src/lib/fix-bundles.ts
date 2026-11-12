/**
 * Companion classpath adjustments required by specific vulnerability fixes.
 *
 * A bare version pin is sometimes an incomplete fix: applying it can change runtime behavior in
 * ways no compile check sees (see the CVE-2026-92877 entry). Each bundle names coordinates that
 * must be excluded from the dependency graph whenever any of its advisories' fixes are present —
 * applied this run, or already pinned with the advisory in a managed-block `because` clause.
 *
 * Remove an entry once its precondition goes away (e.g. a patched release moves the pin on).
 */
export interface FixBundleExclusion {
  /** Maven coordinate to exclude from all configurations: "group:artifact". */
  coordinate: string;
  /** Human-readable reason, rendered as a comment above the exclusion in the managed block. */
  reason: string;
}

export const FIX_BUNDLES: Record<string, FixBundleExclusion[]> = {
  // jaxb-runtime 3.0.2 — the only fixed release for CVE-2026-92877 — registers only the legacy
  // META-INF/services/jakarta.xml.bind.JAXBContext service file; jakarta.xml.bind-api 4.x never
  // consults that file, so its ContextFinder falls back to an OSGi lookup that throws NPE outside
  // an OSGi runtime whenever osgi-resource-locator (transitive via jersey-common) is on the
  // classpath. Excluding it lets the API fall through to its built-in default provider instead.
  // Revisit this bundle when a patched jaxb-runtime 4.0.x ships (none as of 2026-11).
  "CVE-2026-92877": [
    {
      coordinate: "org.glassfish.hk2:osgi-resource-locator",
      reason: "companion of the CVE-2026-92877 jaxb 3.0.2 pin — jakarta.xml.bind-api 4.x OSGi fallback NPEs when osgi-resource-locator is present",
    },
  ],
};

/** Companion exclusions required by any of the given advisory IDs, deduplicated by coordinate. */
export function companionExclusions(advisoryIds: Iterable<string>): FixBundleExclusion[] {
  const out: FixBundleExclusion[] = [];
  const seen = new Set<string>();
  for (const id of advisoryIds) {
    for (const ex of FIX_BUNDLES[id] ?? []) {
      if (!seen.has(ex.coordinate)) {
        seen.add(ex.coordinate);
        out.push(ex);
      }
    }
  }
  return out;
}
