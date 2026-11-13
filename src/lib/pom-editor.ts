/**
 * POM editor — Apply version bumps to pom.xml.
 *
 * Direct dependencies are rewritten in place. Transitive dependencies get
 * explicit pins inside an auto-bumper managed block (idempotent on re-runs).
 *
 * A parent property is copied into this pom so it wins. A versionless direct dependency gets an explicit version so a BOM cannot keep the old pin. Exclusions are attached to direct dependencies.
 */
import fs from "node:fs";
import {
  POM_MARKER_BEGIN,
  POM_MARKER_END,
  POM_MARKERS,
} from "./brand.ts";
import { compareMavenVersion } from "./matcher.ts";
import type { ApplyResult, BumpRequest, ExcludeRequest, RenameRequest } from "./gradle-editor.ts";

export type { ApplyResult, BumpRequest, ExcludeRequest, RenameRequest };

const MARKER_BEGIN = POM_MARKER_BEGIN;
const MARKER_END = POM_MARKER_END;

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

interface XmlBlock {
  start: number;
  end: number;
  text: string;
}

/** `<dependency>` at `index`, not `<dependencies>` or `<dependencyManagement>`. */
function dependencyTagAt(content: string, index: number): { close: boolean; end: number } | null {
  const close = content.startsWith("</", index);
  const nameAt = index + (close ? 2 : 1);
  if (!content.startsWith("dependency", nameAt)) return null;
  const after = nameAt + "dependency".length;
  const next = content[after];
  if (next !== ">" && next !== "/" && next !== " " && next !== "\t" && next !== "\n" && next !== "\r") return null;
  const gt = content.indexOf(">", after);
  if (gt === -1) return null;
  return { close: close || content[gt - 1] === "/", end: gt + 1 };
}

/**
 * Dependency elements. Comments and CDATA are skipped, so a `</dependency>` inside
 * a comment does not end the block. Nested dependency elements stay inside the outer one.
 */
function dependencyBlocks(content: string): XmlBlock[] {
  const blocks: XmlBlock[] = [];
  let i = 0;
  let depth = 0;
  let start = -1;
  while (i < content.length) {
    if (content.startsWith("<!--", i)) {
      const end = content.indexOf("-->", i + 4);
      i = end === -1 ? content.length : end + 3;
      continue;
    }
    if (content.startsWith("<![CDATA[", i)) {
      const end = content.indexOf("]]>", i + 9);
      i = end === -1 ? content.length : end + 3;
      continue;
    }
    const tag = content[i] === "<" ? dependencyTagAt(content, i) : null;
    if (!tag) {
      i++;
      continue;
    }
    if (tag.close) {
      if (depth > 0) {
        depth--;
        if (depth === 0 && start >= 0) {
          blocks.push({ start, end: tag.end, text: content.slice(start, tag.end) });
          start = -1;
        }
      }
    } else if (depth === 0) {
      start = i;
      depth = 1;
    } else {
      depth++;
    }
    i = tag.end;
  }
  return blocks;
}

/** Replace a run of trailing newlines with `count` newlines; no-op when none present. */
function collapseTrailingNewlines(s: string, count: number): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "\n") end--;
  if (end === s.length) return s;
  return s.slice(0, end) + "\n".repeat(count);
}

/** Ensure the string ends with exactly `count` newlines (adds them when absent). */
function ensureTrailingNewlines(s: string, count: number): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "\n") end--;
  return s.slice(0, end) + "\n".repeat(count);
}

interface DepBlock {
  group: string;
  artifact: string;
  version: string | null;
  start: number;
  end: number;
  managed: boolean;
  inMarker: boolean;
}

/** All <dependency> blocks with coordinates, positions, and section context. */
function findDepBlocks(content: string): DepBlock[] {
  const blocks: DepBlock[] = [];
  const dmStart = content.indexOf("<dependencyManagement>");
  const dmEnd = dmStart >= 0 ? content.indexOf("</dependencyManagement>", dmStart) : -1;
  const regions = findManagedBlocks(content);

  for (const found of dependencyBlocks(content)) {
    const block = found.text;
    const idx = found.start;
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    if (!groupMatch || !artifactMatch) continue;
    const versionMatch = /<version>([^<]+)<\/version>/.exec(block);
    blocks.push({
      group: groupMatch[1].trim(),
      artifact: artifactMatch[1].trim(),
      version: versionMatch ? versionMatch[1].trim() : null,
      start: idx,
      end: idx + block.length,
      managed: dmStart >= 0 && dmEnd > dmStart && idx > dmStart && idx < dmEnd,
      inMarker: regions.some(r => idx >= r.begin && idx <= r.end + r.endLen),
    });
  }
  return blocks;
}

/**
 * The declaration Maven actually uses for a GA: the top-level <dependencies> entry
 * wins over dependencyManagement; auto-bumper pin blocks never count.
 */
function pickEffectiveBlock(blocks: DepBlock[], group: string, artifact: string): DepBlock | null {
  const matches = blocks.filter(b => b.group === group && b.artifact === artifact && !b.inMarker);
  if (matches.length === 0) return null;
  return matches.find(b => !b.managed) ?? matches[0];
}

/** Write a version property in this pom. A local property overrides the same name from a parent. */
function defineLocalProperty(content: string, propName: string, version: string): string {
  const propRe = new RegExp(`(<${escapeRegex(propName)}>)([^<]+)(</${escapeRegex(propName)}>)`);
  if (propRe.test(content)) {
    return content.replace(propRe, (_m, pre, _old, post) => `${pre}${version}${post}`);
  }
  const entry = `        <${propName}>${version}</${propName}>`;
  const props = /<properties>\s*/.exec(content);
  if (props) {
    const idx = props.index + props[0].length;
    return `${content.slice(0, idx)}${entry}\n${content.slice(idx)}`;
  }
  const projectOpen = /<project\b[^>]*>/.exec(content);
  if (!projectOpen) return content;
  const idx = projectOpen.index + projectOpen[0].length;
  return `${content.slice(0, idx)}\n    <properties>\n${entry}\n    </properties>${content.slice(idx)}`;
}

function rewriteDirect(
  content: string,
  bump: BumpRequest,
  warnings: string[],
): { content: string; changed: boolean } {
  const [group, artifact] = bump.packageName.split(":");
  if (!group || !artifact) {
    warnings.push(`${bump.packageName}: not a valid group:artifact coordinate`);
    return { content, changed: false };
  }

  const effective = pickEffectiveBlock(findDepBlocks(content), group, artifact);
  if (!effective) return { content, changed: false };

  if (effective.version == null) {
    if (effective.managed) return { content, changed: false };
    const block = content.slice(effective.start, effective.end);
    const injected = block.replace(
      /<\/dependency>\s*$/,
      `  <version>${bump.targetVersion}</version>\n</dependency>`,
    );
    content = content.slice(0, effective.start) + injected + content.slice(effective.end);
    return { content, changed: true };
  }

  if (/\$\{/.test(effective.version)) {
    const propName = effective.version.replace(/^\$\{|\}$/g, "");
    if (!/^[\w.-]+$/.test(propName)) {
      warnings.push(`${bump.packageName}: version property \${${propName}} is not a local name — falling back to pin`);
      return { content, changed: false };
    }
    const hadProperty = new RegExp(`<${escapeRegex(propName)}>`).test(content);
    content = defineLocalProperty(content, propName, bump.targetVersion);
    warnings.push(
      hadProperty
        ? `${bump.packageName}: bumped via property \${${propName}} — other deps using it move too`
        : `${bump.packageName}: defined \${${propName}} in this pom so it overrides the parent — other deps using it move too`,
    );
    return { content, changed: true };
  }

  const newBlock = content.slice(effective.start, effective.end).replace(
    /<version>[^<]+<\/version>/,
    `<version>${bump.targetVersion}</version>`,
  );
  content = content.slice(0, effective.start) + newBlock + content.slice(effective.end);
  return { content, changed: true };
}

function renderPinDependency(pkg: string, version: string): string {
  const [group, artifact] = pkg.split(":");
  return [
    "  <dependency>",
    `    <groupId>${group}</groupId>`,
    `    <artifactId>${artifact}</artifactId>`,
    `    <version>${version}</version>`,
    "  </dependency>",
  ].join("\n");
}

function parseExistingPins(block: string): Map<string, string> {
  const entries = new Map<string, string>();
  for (const dep of dependencyBlocks(block).map(found => found.text)) {
    const group = /<groupId>([^<]+)<\/groupId>/.exec(dep)?.[1]?.trim();
    const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(dep)?.[1]?.trim();
    const version = /<version>([^<]+)<\/version>/.exec(dep)?.[1]?.trim();
    if (group && artifact && version) entries.set(`${group}:${artifact}`, version);
  }
  return entries;
}

/** Free-text bucket keys for comments that document the block rather than one pin. */
const FREE_TEXT_HEADER = "\u0000header";
const FREE_TEXT_FOOTER = "\u0000footer";

/**
 * Bucket user comments from an existing managed block by the pin they document, so a
 * re-render keeps them above their entry. A comment attaches to the NEXT <dependency>
 * below it (or to the footer when nothing follows). Blank lines are dropped (the
 * renderer owns layout); multi-line XML comments are captured whole.
 */
function parsePomBlockFreeText(block: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let pending: string[] = [];
  let inComment = false;
  const flush = (key: string) => {
    if (pending.length === 0) return;
    const lines = out.get(key);
    if (lines) lines.push(...pending);
    else out.set(key, [...pending]);
    pending = [];
  };
  const lines = block.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === "") continue;
    if (POM_MARKERS.some(m => m.begin === trimmed || m.end === trimmed)) {
      if (POM_MARKERS.some(m => m.end === trimmed)) flush(FREE_TEXT_FOOTER);
      continue;
    }
    if (inComment) {
      pending.push(trimmed);
      if (trimmed.includes("-->")) inComment = false;
      continue;
    }
    if (trimmed.startsWith("<!--")) {
      pending.push(trimmed);
      if (!trimmed.includes("-->")) inComment = true;
      continue;
    }
    if (trimmed.startsWith("<dependency>")) {
      let span = lines[i];
      let j = i;
      while (!span.includes("</dependency>") && j + 1 < lines.length) {
        j++;
        span += "\n" + lines[j];
      }
      const group = /<groupId>([^<]+)<\/groupId>/.exec(span)?.[1]?.trim();
      const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(span)?.[1]?.trim();
      if (group && artifact) flush(`${group}:${artifact}`);
      i = j;
      continue;
    }
    // Unrecognized structural line: treat pending text as block-level.
    flush(FREE_TEXT_HEADER);
  }
  flush(FREE_TEXT_FOOTER);
  return out;
}

/** Drop preserved comments whose pin no longer exists. */
function prunePomFreeText(
  freeText: Map<string, string[]> | null,
  entries: Map<string, string>,
): Map<string, string[]> | null {
  if (!freeText || freeText.size === 0) return freeText;
  const out = new Map<string, string[]>();
  for (const [key, lines] of freeText) {
    if (key === FREE_TEXT_HEADER || key === FREE_TEXT_FOOTER || entries.has(key)) out.set(key, lines);
  }
  return out;
}

/** Preserved comments for a pin, indented to align with <dependency>. */
function pomFreeTextLines(freeText: Map<string, string[]> | null, key: string, indent: string): string[] {
  const lines = freeText?.get(key) ?? [];
  return lines.map(l => `${indent}${l}`);
}

/** Render the managed block as XML, preserving user comments. */
function renderManagedBlock(entries: Map<string, string>, freeText: Map<string, string[]> | null = null): string {
  const lines = [MARKER_BEGIN];
  lines.push(...pomFreeTextLines(freeText, FREE_TEXT_HEADER, "  "));
  const sorted = [...entries.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [pkg, version] of sorted) {
    lines.push(...pomFreeTextLines(freeText, pkg, "  "));
    lines.push(renderPinDependency(pkg, version));
  }
  lines.push(...pomFreeTextLines(freeText, FREE_TEXT_FOOTER, "  "));
  lines.push(MARKER_END);
  return lines.join("\n");
}

interface ManagedRegion {
  begin: number;
  end: number;
  endLen: number;
}

/** All managed blocks present (any recognized brand), in POM_MARKERS priority order. */
function findManagedBlocks(content: string): ManagedRegion[] {
  const regions: ManagedRegion[] = [];
  for (const { begin, end } of POM_MARKERS) {
    let from = 0;
    for (;;) {
      const beginIdx = content.indexOf(begin, from);
      if (beginIdx === -1) break;
      const endIdx = content.indexOf(end, beginIdx + begin.length);
      if (endIdx === -1) break;
      regions.push({ begin: beginIdx, end: endIdx, endLen: end.length });
      from = endIdx + end.length;
    }
  }
  return regions;
}

/** Consolidate several managed blocks (different tool brands) into the highest-priority one. */
function consolidateManagedBlocks(content: string): string {
  let base = content;
  for (;;) {
    const regions = findManagedBlocks(base);
    if (regions.length <= 1) return base;
    const victim = regions[regions.length - 1]!; // lowest brand priority
    const before = collapseTrailingNewlines(base.slice(0, victim.begin), 1);
    const after = base.slice(victim.end + victim.endLen).replace(/^\n+/, "\n");
    base = `${before}${after}`;
  }
}

/** Merged pins/comments of every managed block (brand priority decides conflicts — canonical wins). */
function parseAllManagedPins(content: string): { entries: Map<string, string>; freeText: Map<string, string[]> | null } {
  const entries = new Map<string, string>();
  let freeText: Map<string, string[]> | null = null;
  for (const region of findManagedBlocks(content)) {
    const existing = content.slice(region.begin, region.end + region.endLen);
    for (const [pkg, v] of parseExistingPins(existing)) if (!entries.has(pkg)) entries.set(pkg, v);
    const ft = parsePomBlockFreeText(existing);
    if (ft.size > 0) {
      for (const [key, lines] of ft) {
        const prev = freeText?.get(key);
        if (prev) prev.push(...lines);
        else (freeText ??= new Map()).set(key, [...lines]);
      }
    }
  }
  return { entries, freeText };
}

function upsertManagedBlock(content: string, pins: BumpRequest[], directlyHandled: string[] = []): string {
  // Merge any legacy-brand blocks into one before upserting, so the file ends with a single block.
  const merged = parseAllManagedPins(content);
  content = consolidateManagedBlocks(content);
  const found = findManagedBlocks(content)[0] ?? null;

  let entries = new Map<string, string>();
  let before = content;
  let after = "";
  let hasBlock = found !== null;
  let freeText: Map<string, string[]> | null = null;

  if (found) {
    const { begin: beginIdx, end: endIdx, endLen } = found;
    // Parsed across every brand's block before consolidation — dropped blocks' pins carry over.
    entries = merged.entries;
    freeText = merged.freeText;
    before = collapseTrailingNewlines(content.slice(0, beginIdx), 1);
    after = content.slice(endIdx + endLen).replace(/^\n+/, "\n");
  }

  for (const pin of pins) {
    entries.set(pin.packageName, pin.targetVersion);
  }
  // A pin is redundant once the package has a declaration Maven actually uses.
  for (const ga of directlyHandled) entries.delete(ga);
  if (entries.size === 0) return hasBlock ? `${before}${after}` : content;

  const block = renderManagedBlock(entries, prunePomFreeText(freeText, entries));
  if (hasBlock) {
    // A misplaced marker (e.g. left between </dependencies> and
    // </dependencyManagement>) must be relocated, not kept in place.
    const lastOpen = before.lastIndexOf("<dependencies>");
    const lastClose = before.lastIndexOf("</dependencies>");
    const dmStart = content.indexOf("<dependencyManagement>");
    const valid = lastOpen !== -1 && lastClose < lastOpen && dmStart !== -1 && dmStart < lastOpen;
    if (!valid) {
      content = `${before}${after}`;
    } else {
      return `${before}${block}${after}`;
    }
  }

  // Pins only take effect inside <dependencyManagement>; a top-level
  // <dependencies> entry would declare a real runtime dependency.
  const dmClose = /<dependencyManagement>(?:(?!<\/dependencyManagement>)[\s\S])*?(?=<\/dependencies>)/.exec(content);
  if (dmClose) {
    const idx = dmClose.index + dmClose[0].length;
    return `${content.slice(0, idx)}\n${block}\n${content.slice(idx)}`;
  }

  const dmSection = `<dependencyManagement>\n    <dependencies>\n${block}\n    </dependencies>\n</dependencyManagement>\n`;
  const depsOpen = /<dependencies>/.exec(content);
  if (depsOpen) {
    return `${content.slice(0, depsOpen.index)}${dmSection}${content.slice(depsOpen.index)}`;
  }

  const projectClose = /<\/project>/.exec(content);
  const projIdx = projectClose?.index;
  if (projIdx !== undefined) {
    return `${content.slice(0, projIdx)}${dmSection}${content.slice(projIdx)}`;
  }

  return `${ensureTrailingNewlines(content, 2)}${dmSection}`;
}
/**
 * Remove an auto-bumper pin for a package from the managed block.
 * Used to roll back bumps whose target version cannot be resolved (e.g. yanked releases).
 * Returns true when the file was modified.
 */
export function removeManagedPin(filePath: string, packageName: string): boolean {
  let content = fs.readFileSync(filePath, "utf-8");
  const merged = parseAllManagedPins(content);
  if (!merged.entries.delete(packageName)) return false;
  content = consolidateManagedBlocks(content);
  const found = findManagedBlocks(content)[0];
  if (found) {
    const before = collapseTrailingNewlines(content.slice(0, found.begin), 1);
    const after = content.slice(found.end + found.endLen).replace(/^\n+/, "");
    content = merged.entries.size > 0
      ? `${before}${renderManagedBlock(merged.entries, prunePomFreeText(merged.freeText, merged.entries))}\n${after}`
      : `${before}${after}`;
  }
  fs.writeFileSync(filePath, content, "utf-8");
  return true;
}

function rewriteRename(
  content: string,
  rename: RenameRequest,
  warnings: string[],
): { content: string; changed: boolean } {
  const [fromGroup, fromArt] = rename.fromPackage.split(":");
  const [toGroup, toArt] = rename.toPackage.split(":");
  if (!fromGroup || !fromArt || !toGroup || !toArt) {
    warnings.push(`${rename.fromPackage}: invalid rename coordinates`);
    return { content, changed: false };
  }

  const bump: BumpRequest = {
    packageName: rename.fromPackage,
    targetVersion: rename.targetVersion,
    because: rename.because,
  };
  let { content: next, changed } = rewriteDirect(content, bump, warnings);

  const edits: Array<{ start: number; end: number; text: string }> = [];
  for (const found of dependencyBlocks(next)) {
    const block = found.text;
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    if (!groupMatch || !artifactMatch) continue;
    if (groupMatch[1].trim() !== fromGroup || artifactMatch[1].trim() !== fromArt) continue;

    edits.push({
      start: found.start,
      end: found.end,
      text: block
        .replace(/<groupId>[^<]+<\/groupId>/, `<groupId>${toGroup}</groupId>`)
        .replace(/<artifactId>[^<]+<\/artifactId>/, `<artifactId>${toArt}</artifactId>`),
    });
  }
  edits.sort((a, b) => b.start - a.start);
  for (const edit of edits) {
    next = next.slice(0, edit.start) + edit.text + next.slice(edit.end);
    changed = true;
  }

  return { content: next, changed };
}

/** Group bumps that share one ${prop} version placeholder. */
function groupSharedPropertyBumps(
  bumps: BumpRequest[],
  blocks: DepBlock[],
): Map<string, BumpRequest[]> {
  const byProperty = new Map<string, BumpRequest[]>();
  for (const bump of bumps) {
    const [group, artifact] = bump.packageName.split(":");
    if (!group || !artifact) continue;
    const effective = pickEffectiveBlock(blocks, group, artifact);
    if (!effective?.version || !/^\$\{[^}]+\}$/.test(effective.version)) continue;
    const propName = effective.version.slice(2, -1);
    if (!/^[\w.-]+$/.test(propName)) continue;
    byProperty.set(propName, [...(byProperty.get(propName) ?? []), bump]);
  }
  return byProperty;
}

/** Highest Maven version among the given targets. */
function highestMavenTarget(targets: string[]): string {
  return targets.reduce((max, v) => (compareMavenVersion(v, max) > 0 ? v : max), targets[0]);
}

/** Rewrite one shared version property to its highest target; no-op when targets conflict across groups. */
function applySharedPropertyRewrite(
  content: string,
  propName: string,
  groupBumps: BumpRequest[],
  result: ApplyResult,
): string {
  const groupId = groupBumps[0].packageName.split(":")[0];
  if (!groupBumps.every(b => b.packageName.split(":")[0] === groupId)) {
    result.warnings.push(
      `\${${propName}} is shared by ${groupBumps.length} packages from different groups with conflicting targets — applying sequentially, verify resolution manually`,
    );
    return content;
  }
  const maxTarget = highestMavenTarget(groupBumps.map(b => b.targetVersion));
  for (const b of groupBumps) result.direct.push(b.packageName);
  const others = groupBumps.length > 1 ? ` (+${groupBumps.length - 1} shared)` : "";
  const hadProperty = new RegExp(`<${escapeRegex(propName)}>`).test(content);
  result.warnings.push(
    hadProperty
      ? `${groupBumps[0].packageName}: bumped via property \${${propName}} to ${maxTarget}${others} — other deps using it move too`
      : `${groupBumps[0].packageName}: defined \${${propName}} in this pom so it overrides the parent — other deps using it move too`,
  );
  return defineLocalProperty(content, propName, maxTarget);
}

function dependencyManagementSpans(content: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const re = /<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(content)) !== null) {
    spans.push([match.index, match.index + match[0].length]);
  }
  return spans;
}

function insideSpan(index: number, spans: Array<[number, number]>): boolean {
  return spans.some(([start, end]) => index >= start && index < end);
}

function blockHasExclusion(block: string, group: string, artifact: string): boolean {
  const re = new RegExp(
    String.raw`<exclusion>[\s\S]*?<groupId>\s*${escapeRegex(group)}\s*</groupId>[\s\S]*?<artifactId>\s*${escapeRegex(artifact)}\s*</artifactId>[\s\S]*?</exclusion>`,
  );
  return re.test(block);
}

function blockCoordinates(block: string): string | null {
  const group = /<groupId>([^<]+)<\/groupId>/.exec(block)?.[1]?.trim();
  const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(block)?.[1]?.trim();
  if (!group || !artifact) return null;
  return `${group}:${artifact}`;
}

function insertExclusion(block: string, group: string, artifact: string): string {
  const exclusion = [
    "      <exclusion>",
    `        <groupId>${group}</groupId>`,
    `        <artifactId>${artifact}</artifactId>`,
    "      </exclusion>",
  ].join("\n");
  if (/<exclusions>/.test(block)) {
    return block.replace("<exclusions>", `<exclusions>\n${exclusion}`);
  }
  return block.replace(
    "</dependency>",
    `    <exclusions>\n${exclusion}\n    </exclusions>\n  </dependency>`,
  );
}

/** Attach each coordinate as an <exclusion> on direct dependencies. dependencyManagement cannot exclude transitives. */
function applyMavenExclusions(content: string, excludes: ExcludeRequest[], result: ApplyResult): string {
  if (excludes.length === 0) return content;
  const spans = dependencyManagementSpans(content);
  let next = content;
  for (const ex of excludes) {
    next = applyOneExclusion(next, ex, spans, result);
  }
  return next;
}

/** Attach one exclusion to every direct dependency block outside dependencyManagement (or only to ex.attachTo when scoped). */
function applyOneExclusion(
  content: string,
  ex: ExcludeRequest,
  spans: Array<[number, number]>,
  result: ApplyResult,
): string {
  const [group, artifact] = ex.packageName.split(":");
  if (!group || !artifact) {
    result.warnings.push(`${ex.packageName}: not a valid group:artifact exclusion`);
    return content;
  }
  const scopedTo = ex.attachTo && ex.attachTo.length > 0 ? new Set(ex.attachTo) : null;
  const edits: Array<{ start: number; end: number; text: string }> = [];
  let already = false;
  for (const found of dependencyBlocks(content)) {
    const { start, end } = found;
    const block = found.text;
    if (insideSpan(start, spans)) continue;
    if (blockCoordinates(block) === ex.packageName) continue;
    if (scopedTo && !scopedTo.has(blockCoordinates(block) ?? "")) continue;
    if (blockHasExclusion(block, group, artifact)) {
      already = true;
      continue;
    }
    edits.push({
      start,
      end,
      text: insertExclusion(block, group, artifact),
    });
  }
  if (edits.length === 0 && !already) {
    result.warnings.push(scopedTo ? `${ex.packageName}: none of its resolved sources (${[...scopedTo].join(", ")}) are direct dependencies — nothing to attach <exclusion> to` : `${ex.packageName}: no direct dependency to attach <exclusion> to`);
    return content;
  }
  edits.sort((a, b) => b.start - a.start);
  let next = content;
  for (const edit of edits) {
    next = next.slice(0, edit.start) + edit.text + next.slice(edit.end);
  }
  result.excluded.push(ex.packageName);
  return next;
}

export function applyBumps(
  filePath: string,
  bumps: BumpRequest[],
  excludes: ExcludeRequest[] = [],
): ApplyResult {
  const result: ApplyResult = { direct: [], constrained: [], excluded: [], forced: [], warnings: [] };
  if (bumps.length === 0 && excludes.length === 0) return result;

  let content = fs.readFileSync(filePath, "utf-8");
  content = applyMavenExclusions(content, excludes, result);
  const pins: BumpRequest[] = [];
  const blocks = findDepBlocks(content);

  // Several artifacts may share one version property with different fix targets.
  // Rewrite each shared property once to the highest target so no later bump
  // regresses an earlier one. Grouping is restricted to a single groupId —
  // over-bumping across vendors could select a nonexistent version.
  const byProperty = groupSharedPropertyBumps(bumps, blocks);

  for (const [propName, groupBumps] of byProperty) {
    content = applySharedPropertyRewrite(content, propName, groupBumps, result);
  }

  for (const bump of bumps) {
    if (result.direct.includes(bump.packageName)) continue;
    const { content: next, changed } = rewriteDirect(content, bump, result.warnings);
    content = next;
    if (changed) {
      result.direct.push(bump.packageName);
    } else {
      pins.push(bump);
      result.constrained.push(bump.packageName);
    }
  }

  content = upsertManagedBlock(content, pins, result.direct);
  fs.writeFileSync(filePath, content, "utf-8");
  return result;
}

export function applyRenames(filePath: string, renames: RenameRequest[]): ApplyResult {
  const result: ApplyResult = { direct: [], constrained: [], excluded: [], forced: [], warnings: [] };
  if (renames.length === 0) return result;

  let content = fs.readFileSync(filePath, "utf-8");
  const pins: BumpRequest[] = [];
  const renamedFrom: string[] = [];

  for (const rename of renames) {
    const { content: next, changed } = rewriteRename(content, rename, result.warnings);
    content = next;
    const label = `${rename.fromPackage} -> ${rename.toPackage}`;
    if (changed) {
      result.direct.push(label);
      renamedFrom.push(rename.fromPackage);
    } else {
      pins.push({
        packageName: rename.toPackage,
        targetVersion: rename.targetVersion,
        because: rename.because,
      });
      result.constrained.push(label);
    }
  }

  content = upsertManagedBlock(content, pins, renamedFrom);
  fs.writeFileSync(filePath, content, "utf-8");
  return result;
}

export { backupPath, backupFile as backupPomXml, restoreFile as restorePomXml, discardBackup } from "./backup.ts";
