/** Product branding — keep in sync with package name @elephantseed/auto-bumper */

export const PRODUCT_NAME = "Auto-Bumper";
export const LOG_PREFIX = "[Auto-Bumper]";

export const BACKUP_SUFFIX = ".auto-bumper-bak";
export const LEGACY_BACKUP_SUFFIX = ".depender-bak";

export const GRADLE_MARKER_BEGIN = "// auto-bumper:begin managed constraints (auto-generated, do not edit)";
export const GRADLE_MARKER_END = "// auto-bumper:end";
/** Marker set written by an earlier "auto-depender" build of this tool. */
export const AUTO_DEPENDER_GRADLE_MARKER_BEGIN = "// auto-depender:begin managed constraints (auto-generated, do not edit)";
export const AUTO_DEPENDER_GRADLE_MARKER_END = "// auto-depender:end";
export const LEGACY_GRADLE_MARKER_BEGIN = "// depender:begin managed constraints (auto-generated, do not edit)";
export const LEGACY_GRADLE_MARKER_END = "// depender:end";

export const POM_MARKER_BEGIN = "<!-- auto-bumper:begin managed pins (auto-generated, do not edit) -->";
export const POM_MARKER_END = "<!-- auto-bumper:end -->";
/** Marker set written by an earlier "auto-depender" build of this tool. */
export const AUTO_DEPENDER_POM_MARKER_BEGIN = "<!-- auto-depender:begin managed pins (auto-generated, do not edit) -->";
export const AUTO_DEPENDER_POM_MARKER_END = "<!-- auto-depender:end -->";
export const LEGACY_POM_MARKER_BEGIN = "<!-- depender:begin managed pins (auto-generated, do not edit) -->";
export const LEGACY_POM_MARKER_END = "<!-- depender:end -->";

/**
 * Recognized managed-block marker sets, highest brand priority first. Priority decides which
 * block survives when several coexist (canonical wins conflicts) and where the consolidated
 * block is re-rendered; on rewrite every block migrates to the canonical markers.
 */
export const GRADLE_MARKERS = [
  { begin: GRADLE_MARKER_BEGIN, end: GRADLE_MARKER_END },
  { begin: AUTO_DEPENDER_GRADLE_MARKER_BEGIN, end: AUTO_DEPENDER_GRADLE_MARKER_END },
  { begin: LEGACY_GRADLE_MARKER_BEGIN, end: LEGACY_GRADLE_MARKER_END },
] as const;

export const POM_MARKERS = [
  { begin: POM_MARKER_BEGIN, end: POM_MARKER_END },
  { begin: AUTO_DEPENDER_POM_MARKER_BEGIN, end: AUTO_DEPENDER_POM_MARKER_END },
  { begin: LEGACY_POM_MARKER_BEGIN, end: LEGACY_POM_MARKER_END },
] as const;

