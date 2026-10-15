/**
 * POM editor — Apply version bumps to pom.xml.
 *
 * Direct dependencies are rewritten in place. Transitive dependencies get
 * explicit pins inside an auto-bumper managed block (idempotent on re-runs).
 *
 * v1 limitations: no property/BOM inheritance resolution. Exclusions are attached to direct dependencies.
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
  const markerBegin = content.indexOf(MARKER_BEGIN);
  const markerEnd = markerBegin >= 0 ? content.indexOf(MARKER_END, markerBegin) : -1;

  const re = /<dependency>[\s\S]*?<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const block = m[0];
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    if (!groupMatch || !artifactMatch) continue;
    const versionMatch = /<version>([^<]+)<\/version>/.exec(block);
    blocks.push({
      group: groupMatch[1].trim(),
      artifact: artifactMatch[1].trim(),
      version: versionMatch ? versionMatch[1].trim() : null,
      start: m.index,
      end: m.index + block.length,
      managed: dmStart >= 0 && dmEnd > dmStart && m.index > dmStart && m.index < dmEnd,
      inMarker: markerBegin >= 0 && markerEnd > markerBegin && m.index >= markerBegin && m.index <= markerEnd,
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
  if (effective?.version == null) return { content, changed: false };

  if (/\$\{/.test(effective.version)) {
    const propName = effective.version.replace(/^\$\{|\}$/g, "");
    const propRe = new RegExp(`(<${escapeRegex(propName)}>)([^<]+)(</${escapeRegex(propName)}>)`);
    if (!propRe.test(content)) {
      warnings.push(
        `${bump.packageName}: version property \${${propName}} not found in <properties> — falling back to pin`,
      );
      return { content, changed: false };
    }
    content = content.replace(propRe, (_m, pre, _old, post) => `${pre}${bump.targetVersion}${post}`);
    warnings.push(
      `${bump.packageName}: bumped via property \${${propName}} — other deps using it move too`,
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
  for (const dep of block.match(/<dependency>[\s\S]*?<\/dependency>/g) || []) {
    const group = /<groupId>([^<]+)<\/groupId>/.exec(dep)?.[1]?.trim();
    const artifact = /<artifactId>([^<]+)<\/artifactId>/.exec(dep)?.[1]?.trim();
    const version = /<version>([^<]+)<\/version>/.exec(dep)?.[1]?.trim();
    if (group && artifact && version) entries.set(`${group}:${artifact}`, version);
  }
  return entries;
}

function renderManagedBlock(entries: Map<string, string>): string {
  const lines = [MARKER_BEGIN];
  const sorted = [...entries.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [pkg, version] of sorted) {
    lines.push(renderPinDependency(pkg, version));
  }
  lines.push(MARKER_END);
  return lines.join("\n");
}

function findManagedBlock(content: string): { begin: number; end: number; endLen: number } | null {
  for (const { begin, end } of POM_MARKERS) {
    const beginIdx = content.indexOf(begin);
    const endIdx = content.indexOf(end);
    if (beginIdx !== -1 && endIdx !== -1 && endIdx > beginIdx) {
      return { begin: beginIdx, end: endIdx, endLen: end.length };
    }
  }
  return null;
}

function upsertManagedBlock(content: string, pins: BumpRequest[], directlyHandled: string[] = []): string {
  const found = findManagedBlock(content);

  let entries = new Map<string, string>();
  let before = content;
  let after = "";
  let hasBlock = found !== null;

  if (found) {
    const { begin: beginIdx, end: endIdx, endLen } = found;
    const existing = content.slice(beginIdx, endIdx + endLen);
    entries = parseExistingPins(existing);
    before = collapseTrailingNewlines(content.slice(0, beginIdx), 1);
    after = content.slice(endIdx + endLen).replace(/^\n+/, "\n");
  }

  for (const pin of pins) {
    entries.set(pin.packageName, pin.targetVersion);
  }
  // A pin is redundant once the package has a declaration Maven actually uses.
  for (const ga of directlyHandled) entries.delete(ga);
  if (entries.size === 0) return hasBlock ? `${before}${after}` : content;

  const block = renderManagedBlock(entries);
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
  const content = fs.readFileSync(filePath, "utf-8");
  const found = findManagedBlock(content);
  if (!found) return false;

  const { begin: beginIdx, end: endIdx, endLen } = found;
  const block = content.slice(beginIdx, endIdx + endLen);
  const entries = parseExistingPins(block);
  if (!entries.delete(packageName)) return false;

  const before = collapseTrailingNewlines(content.slice(0, beginIdx), 1);
  const after = content.slice(endIdx + endLen).replace(/^\n+/, "");
  if (entries.size === 0) {
    fs.writeFileSync(filePath, `${before}${after}`);
    return true;
  }
  const next = renderManagedBlock(entries);
  fs.writeFileSync(filePath, `${before}${next}\n${after}`);
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

  const depBlocks = next.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
  for (const block of depBlocks) {
    const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
    const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
    if (!groupMatch || !artifactMatch) continue;
    if (groupMatch[1].trim() !== fromGroup || artifactMatch[1].trim() !== fromArt) continue;

    const updated = block
      .replace(/<groupId>[^<]+<\/groupId>/, `<groupId>${toGroup}</groupId>`)
      .replace(/<artifactId>[^<]+<\/artifactId>/, `<artifactId>${toArt}</artifactId>`);
    next = next.replace(block, updated);
    changed = true;
  }

  return { content: next, changed };
}

/** Group bumps that share one ${prop} version placeholder. */
function groupSharedPropertyBumps(
  bumps: BumpRequest[],
  blocks: DepBlock[],
  content: string,
): Map<string, BumpRequest[]> {
  const byProperty = new Map<string, BumpRequest[]>();
  for (const bump of bumps) {
    const [group, artifact] = bump.packageName.split(":");
    if (!group || !artifact) continue;
    const effective = pickEffectiveBlock(blocks, group, artifact);
    if (!effective?.version || !/^\$\{[^}]+\}$/.test(effective.version)) continue;
    const propName = effective.version.slice(2, -1);
    const propRe = new RegExp(`(<${escapeRegex(propName)}>)([^<]+)(</${escapeRegex(propName)}>)`);
    if (!propRe.test(content)) continue;
    byProperty.set(propName, [...(byProperty.get(propName) ?? []), bump]);
  }
  return byProperty;
}

/** Highest Maven version among the given targets. */
function highestMavenTarget(targets: string[]): string {
  return targets.reduce((max, v) => (compareMavenVersion(v, max) > 0 ? v : max), targets[0]);
}

/** Rewrite one <prop>...</prop> value in place. */
function rewriteSharedProperty(content: string, propName: string, targetVersion: string): string {
  const propRe = new RegExp(`(<${escapeRegex(propName)}>)([^<]+)(</${escapeRegex(propName)}>)`);
  return content.replace(propRe, (_m, pre, _old, post) => `${pre}${targetVersion}${post}`);
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
  result.warnings.push(
    `${groupBumps[0].packageName}: bumped via property \${${propName}} to ${maxTarget}${others} — other deps using it move too`,
  );
  return rewriteSharedProperty(content, propName, maxTarget);
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
    const [group, artifact] = ex.packageName.split(":");
    if (!group || !artifact) {
      result.warnings.push(`${ex.packageName}: not a valid group:artifact exclusion`);
      continue;
    }
    const re = /<dependency>[\s\S]*?<\/dependency>/g;
    const edits: Array<{ start: number; end: number; text: string }> = [];
    let already = false;
    let match: RegExpExecArray | null;
    while ((match = re.exec(next)) !== null) {
      if (insideSpan(match.index, spans)) continue;
      const block = match[0];
      if (blockCoordinates(block) === ex.packageName) continue;
      if (blockHasExclusion(block, group, artifact)) {
        already = true;
        continue;
      }
      edits.push({
        start: match.index,
        end: match.index + block.length,
        text: insertExclusion(block, group, artifact),
      });
    }
    if (edits.length === 0 && !already) {
      result.warnings.push(`${ex.packageName}: no direct dependency to attach <exclusion> to`);
      continue;
    }
    for (const edit of edits.sort((a, b) => b.start - a.start)) {
      next = next.slice(0, edit.start) + edit.text + next.slice(edit.end);
    }
    result.excluded.push(ex.packageName);
  }
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
  const byProperty = groupSharedPropertyBumps(bumps, blocks, content);

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
