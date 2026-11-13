/**
 * Combine two advisory records that share an id.
 * Affected blocks are retained separately because their version lists and ranges
 * can have different matching authority.
 */
import type { AdvisoryEntry } from "./types.ts";
import { dropUnboundedRangesShadowedByFix } from "./matcher.ts";

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

function unionAffected(a: AdvisoryEntry["affected"], b: AdvisoryEntry["affected"]): AdvisoryEntry["affected"] {
  const seen = new Set<string>();
  const out: AdvisoryEntry["affected"] = [];
  for (const block of [...(a ?? []), ...(b ?? [])]) {
    const copy = structuredClone(block);
    if (copy.ranges) {
      copy.ranges = dropUnboundedRangesShadowedByFix(copy.ranges, copy.package?.ecosystem ?? "");
    }
    const key = JSON.stringify(copy);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(copy);
  }
  return out;
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
