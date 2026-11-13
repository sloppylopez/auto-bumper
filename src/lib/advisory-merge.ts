/**
 * Combine two advisory records that share an id.
 * Affected packages are unioned. Ranges for the same package are concatenated
 * so a richer record cannot drop another package or a newer fixed version.
 * A range with no fix boundary is then dropped when it only restates a window
 * a sibling range already closed.
 */
import type { AdvisoryEntry } from "./types.ts";
import { dropUnboundedRangesShadowedByFix } from "./matcher.ts";

type AffectedBlock = AdvisoryEntry["affected"][number];

function packageKey(block: AffectedBlock): string {
  const name = block.package?.name ?? "";
  const eco = block.package?.ecosystem ?? "";
  return `${eco.toLowerCase()}\u0000${name.toLowerCase()}`;
}

function blockRichness(block: AffectedBlock): number {
  let score = (block.versions?.length || 0) * 2 + (block.ranges?.length || 0) * 3;
  for (const r of block.ranges || []) {
    const range = r as {
      events?: unknown[];
      database_specific?: { extracted_events?: unknown[] };
    };
    score += range.events?.length || 0;
    score += (range.database_specific?.extracted_events?.length || 0) * 2;
  }
  return score;
}

function unionStrings(a: string[] | undefined, b: string[] | undefined): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of [...(a ?? []), ...(b ?? [])]) {
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

function unionRanges(a: unknown[] | undefined, b: unknown[] | undefined): unknown[] {
  const seen = new Set<string>();
  const out: unknown[] = [];
  for (const range of [...(a ?? []), ...(b ?? [])]) {
    const key = JSON.stringify(range);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(range);
  }
  return out;
}

function unionAffected(a: AdvisoryEntry["affected"], b: AdvisoryEntry["affected"]): AdvisoryEntry["affected"] {
  const order: string[] = [];
  const byKey = new Map<string, AffectedBlock>();
  for (const block of [...(a ?? []), ...(b ?? [])]) {
    const key = packageKey(block);
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, structuredClone(block));
      order.push(key);
      continue;
    }
    const base = blockRichness(block) > blockRichness(prev) ? block : prev;
    const eco = block.package?.ecosystem || prev.package?.ecosystem || "";
    byKey.set(key, {
      ...structuredClone(base),
      ranges: dropUnboundedRangesShadowedByFix(unionRanges(prev.ranges, block.ranges), eco),
      versions: unionStrings(prev.versions, block.versions),
    });
  }
  return order.map((key) => byKey.get(key)!);
}

/** Union aliases, links, ecosystems, severity, and affected packages. The id stays. */
export function unionAdvisory(existing: AdvisoryEntry, incoming: AdvisoryEntry): AdvisoryEntry {
  const summary = (incoming.summary?.length || 0) > (existing.summary?.length || 0)
    ? incoming.summary
    : existing.summary;

  const severitySeen = new Set<string>();
  const severity: AdvisoryEntry["severity"] = [];
  for (const sev of [...(existing.severity ?? []), ...(incoming.severity ?? [])]) {
    const key = `${sev.type}\u0000${sev.score}`;
    if (severitySeen.has(key)) continue;
    severitySeen.add(key);
    severity.push(sev);
  }

  const linkSeen = new Set<string>();
  const links: AdvisoryEntry["links"] = [];
  for (const link of [...(existing.links ?? []), ...(incoming.links ?? [])]) {
    if (!link?.url || linkSeen.has(link.url)) continue;
    linkSeen.add(link.url);
    links.push(link);
  }

  const ecoSeen = new Set<string>();
  const ecosystems: string[] = [];
  for (const eco of [...(existing.ecosystems ?? []), ...(incoming.ecosystems ?? [])]) {
    const key = eco.toLowerCase();
    if (ecoSeen.has(key)) continue;
    ecoSeen.add(key);
    ecosystems.push(eco);
  }

  return {
    id: existing.id,
    aliases: unionStrings(existing.aliases, incoming.aliases),
    ecosystems,
    summary,
    severity,
    affected: unionAffected(existing.affected ?? [], incoming.affected ?? []),
    links,
  };
}
