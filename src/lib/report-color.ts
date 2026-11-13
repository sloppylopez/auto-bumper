/**
 * Terminal color for the fix report. ANSI only — no dependencies.
 * Color is off when NO_COLOR is set, FORCE_COLOR=0, TERM=dumb, or stdout is not a TTY.
 */

const RESET = "\u001b[0m";

const STATUS_LABEL =
  "Unfixable|Remaining|Rolled back|Skipped major|Skipped renames|Warnings|Applied|Planned|Families";
const STATUS_PART = new RegExp(`^(?:${STATUS_LABEL}) \\d+$`);

const STATUS_CODE: Record<string, string> = {
  Unfixable: "31",
  Remaining: "31",
  "Rolled back": "33",
  "Skipped major": "33",
  "Skipped renames": "33",
  Warnings: "33",
  Applied: "32",
  Planned: "36",
  Families: "35",
};

interface SectionTone {
  match: (heading: string) => boolean;
  code: string;
}

const SECTIONS: SectionTone[] = [
  { match: h => h.startsWith("## Unfixable"), code: "31" },
  { match: h => h.startsWith("## Remaining vulnerabilities"), code: "31" },
  {
    match: h =>
      h.startsWith("## Skipped — target not resolvable")
      || h.startsWith("## Skipped major")
      || h.startsWith("## Skipped renames"),
    code: "33",
  },
  { match: h => h.startsWith("## Health warnings"), code: "33" },
  { match: h => h.startsWith("## Applied"), code: "32" },
  { match: h => h.startsWith("## Planned"), code: "36" },
  { match: h => h.startsWith("## Family migrations"), code: "35" },
];

export interface RollbackLine {
  packageName: string;
  from: string;
  to: string;
}

export function stdoutColorEnabled(): boolean {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === "0") return false;
  if (process.env.FORCE_COLOR) return true;
  if (process.env.TERM === "dumb") return false;
  return Boolean(process.stdout.isTTY);
}

export function paint(text: string, code: string, enabled = stdoutColorEnabled()): string {
  if (!enabled || text.length === 0) return text;
  return `\u001b[${code}m${text}${RESET}`;
}

export function uniqueRollbackCount(items: RollbackLine[]): number {
  const keys = new Set(items.map(item => `${item.packageName}\0${item.from}\0${item.to}`));
  return keys.size;
}

/** Collapse identical rollback rows. Repeats become one line with a count. */
export function formatUnresolvableSection(items: RollbackLine[]): string[] {
  if (items.length === 0) return [];
  const groups = new Map<string, { item: RollbackLine; count: number }>();
  for (const item of items) {
    const key = `${item.packageName}\0${item.from}\0${item.to}`;
    const existing = groups.get(key);
    if (existing) existing.count += 1;
    else groups.set(key, { item, count: 1 });
  }
  const unique = groups.size;
  const heading = unique === items.length
    ? `## Skipped — target not resolvable (${items.length})`
    : `## Skipped — target not resolvable (${unique} packages, ${items.length} rollbacks)`;
  const lines = [heading, ""];
  for (const { item, count } of groups.values()) {
    const times = count > 1 ? ` ×${count}` : "";
    lines.push(`- ${item.packageName}: rolled back ${item.from} -> ${item.to}${times} — version ${item.to} not found in project repositories`);
  }
  lines.push("");
  return lines;
}

export function colorizeFixReport(markdown: string, enabled = stdoutColorEnabled()): string {
  if (!enabled) return markdown;
  let code: string | null = null;
  return markdown.split("\n").map(line => {
    if (line.startsWith("# ")) return paint(line, "1", true);
    if (line.startsWith("## ")) {
      const tone = SECTIONS.find(section => section.match(line));
      code = tone?.code ?? null;
      return paint(line, tone ? `1;${tone.code}` : "1", true);
    }
    if (isStatusLine(line)) return colorStatus(line);
    if (!code || line.length === 0) return line;
    return colorBody(line, code);
  }).join("\n");
}

function isStatusLine(line: string): boolean {
  const parts = line.split(" · ");
  return parts.length > 0 && parts.every(part => STATUS_PART.test(part));
}

function colorStatus(line: string): string {
  return line.split(" · ").map(part => {
    const label = part.replace(/ \d+$/, "");
    return paint(part, STATUS_CODE[label] ?? "1", true);
  }).join(" · ");
}

function colorBody(line: string, code: string): string {
  const tone = line.startsWith("- ") && /skipped/i.test(line) ? "33" : code;
  const splitAt = line.indexOf(" — ");
  if (splitAt === -1) return paint(line, tone, true);
  const head = line.slice(0, splitAt);
  const tail = line.slice(splitAt);
  return paint(head, `1;${tone}`, true) + paint(tail, `2;${tone}`, true);
}
