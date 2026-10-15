/**
 * Bridge package-less OSV CVE records (GIT/CPE only) onto Maven coordinates.
 * OSV often publishes NVD conversions without affected.package — querybatch then
 * returns nothing for Maven even when extracted_events have clear version ranges.
 */

export interface BridgeProduct {
  id: string;
  /** Maven name prefixes that trigger orphan-CVE enrichment during scan */
  mavenNamePrefixes: string[];
  cpeProducts: Array<{ vendor: string; product: string }>;
  repos: string[];
  /** HTML pages that list CVE IDs for this product (discovery) */
  advisoryIdSources: string[];
  /** Curated CVE IDs for products without a discoverable security page */
  knownCveIds?: string[];
  resolvePackages: (summary: string, details: string) => string[];
}

/** Products we can recover from package-less OSV/CVE records. Log4j first. */
export const BRIDGE_PRODUCTS: BridgeProduct[] = [
  {
    id: "apache-log4j",
    mavenNamePrefixes: ["org.apache.logging.log4j:"],
    cpeProducts: [{ vendor: "apache", product: "log4j" }],
    repos: [
      "https://github.com/apache/logging-log4j2",
      "http://github.com/apache/logging-log4j2",
      "git://github.com/apache/logging-log4j2",
      "https://github.com/apache/logging-log4j2.git",
    ],
    advisoryIdSources: ["https://logging.apache.org/security.html"],
    resolvePackages(summary, details) {
      const text = `${summary}\n${details}`;
      // CVE text often scopes to the API artifact only
      if (/log4j\s+api/i.test(text)) {
        return ["org.apache.logging.log4j:log4j-api"];
      }
      return [
        "org.apache.logging.log4j:log4j-api",
        "org.apache.logging.log4j:log4j-core",
      ];
    },
  },
  {
    id: "java-json-tools-jackson-coreutils",
    mavenNamePrefixes: ["com.github.java-json-tools:jackson-coreutils"],
    cpeProducts: [],
    repos: [
      "https://github.com/java-json-tools/jackson-coreutils",
      "http://github.com/java-json-tools/jackson-coreutils",
      "git://github.com/java-json-tools/jackson-coreutils",
      "https://github.com/java-json-tools/jackson-coreutils.git",
    ],
    advisoryIdSources: [],
    knownCveIds: ["CVE-2026-86321", "CVE-2026-86513", "CVE-2026-86511"],
    resolvePackages() {
      return ["com.github.java-json-tools:jackson-coreutils"];
    },
  },
  {
    id: "java-json-tools-json-patch",
    mavenNamePrefixes: ["com.github.java-json-tools:json-patch"],
    cpeProducts: [],
    repos: [
      "https://github.com/java-json-tools/json-patch",
      "http://github.com/java-json-tools/json-patch",
      "git://github.com/java-json-tools/json-patch",
      "https://github.com/java-json-tools/json-patch.git",
    ],
    advisoryIdSources: [],
    knownCveIds: ["CVE-2026-86318", "CVE-2026-86319", "CVE-2026-86512"],
    resolvePackages() {
      return ["com.github.java-json-tools:json-patch"];
    },
  },
];

type OsvAffected = {
  package?: { name?: string; ecosystem?: string };
  versions?: string[];
  ranges?: Array<{
    type?: string;
    repo?: string;
    database_specific?: { cpe?: string | string[]; extracted_events?: unknown[] };
  }>;
  database_specific?: unknown;
};

function normalizeRepo(repo: string): string {
  return repo.trim().toLowerCase().replace(/\.git$/, "").replace(/\/$/, "");
}

function parseCpeVendorProduct(cpe: string): { vendor: string; product: string } | null {
  // cpe:2.3:a:apache:log4j:*:...
  const parts = cpe.split(":");
  if (parts.length < 5) return null;
  if (parts[2] !== "a") return null;
  return { vendor: parts[3]!.toLowerCase(), product: parts[4]!.toLowerCase() };
}

function collectCpes(affected: OsvAffected): string[] {
  const out: string[] = [];
  for (const range of affected.ranges || []) {
    const cpe = range.database_specific?.cpe;
    if (!cpe) continue;
    if (Array.isArray(cpe)) out.push(...cpe);
    else out.push(cpe);
  }
  return out;
}

function collectRepos(affected: OsvAffected): string[] {
  const out: string[] = [];
  for (const range of affected.ranges || []) {
    if (range.repo) out.push(range.repo);
  }
  return out;
}

function productMatchesSignals(
  product: BridgeProduct,
  cpes: string[],
  repos: string[],
): boolean {
  for (const cpe of cpes) {
    const parsed = parseCpeVendorProduct(cpe);
    if (!parsed) continue;
    if (product.cpeProducts.some(p => p.vendor === parsed.vendor && p.product === parsed.product)) {
      return true;
    }
  }
  const normalizedRepos = new Set(product.repos.map(normalizeRepo));
  for (const repo of repos) {
    if (normalizedRepos.has(normalizeRepo(repo))) return true;
  }
  return false;
}

/** Resolve Maven package names for a package-less affected block, if bridged. */
export function resolveBridgedMavenPackages(
  affected: OsvAffected,
  summary = "",
  details = "",
): string[] {
  const cpes = collectCpes(affected);
  const repos = collectRepos(affected);
  for (const product of BRIDGE_PRODUCTS) {
    if (!productMatchesSignals(product, cpes, repos)) continue;
    return product.resolvePackages(summary, details);
  }
  return [];
}

/**
 * Fill in Maven package coords on package-less affected blocks using CPE/repo.
 * Leaves already-packaged blocks unchanged.
 */
export function enrichOsvVulnWithBridgedPackages(
  v: Record<string, unknown>,
): Record<string, unknown> {
  const affected = (v.affected as OsvAffected[] | undefined) || [];
  if (affected.length === 0) return v;

  const summary = typeof v.summary === "string" ? v.summary : "";
  const details = typeof v.details === "string" ? v.details : "";
  let changed = false;
  const next: OsvAffected[] = [];

  for (const block of affected) {
    const existing = block.package?.name?.trim();
    if (existing) {
      next.push(block);
      continue;
    }
    const names = resolveBridgedMavenPackages(block, summary, details);
    if (names.length === 0) {
      next.push(block);
      continue;
    }
    changed = true;
    for (const name of names) {
      next.push({
        ...block,
        package: { ecosystem: "Maven", name },
      });
    }
  }

  if (!changed) return v;
  return { ...v, affected: next };
}

/** True when any scanned package belongs to a bridged product. */
export function packagesNeedOrphanBridge(packages: Array<{ ecosystem: string; name: string }>): boolean {
  return packages.some(pkg => {
    if (pkg.ecosystem.toLowerCase() !== "maven") return false;
    const name = pkg.name.toLowerCase();
    return BRIDGE_PRODUCTS.some(p =>
      p.mavenNamePrefixes.some(prefix => name.startsWith(prefix.toLowerCase())),
    );
  });
}

/** Products relevant to the given package set (or all, when packages omitted). */
export function bridgeProductsForPackages(
  packages?: Array<{ ecosystem: string; name: string }>,
): BridgeProduct[] {
  if (!packages) return BRIDGE_PRODUCTS;
  return BRIDGE_PRODUCTS.filter(product =>
    packages.some(pkg => {
      if (pkg.ecosystem.toLowerCase() !== "maven") return false;
      const name = pkg.name.toLowerCase();
      return product.mavenNamePrefixes.some(prefix => name.startsWith(prefix.toLowerCase()));
    }),
  );
}
