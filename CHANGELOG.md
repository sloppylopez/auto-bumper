# Changelog

All notable changes to `@elephantseed/auto-bumper`.

## [0.0.4] - 2026-10-15

### Added
- `fix --apply-excludes` (Maven/Gradle): unfixable packages (no fixed version in OSV) are excluded from the dependency graph instead of being left reported — Gradle gets a managed `configurations.all { exclude … }` block, Maven attaches `<exclusion>` to the parent dependency. Exclusions are recorded only when every touched project actually wrote them; a Maven direct dependency cannot be excluded and is reported with manual-removal advice instead
- `fix --apply` rewrites the lockfile after a manifest edit so the next scan sees the new pins: `npm install --package-lock-only --ignore-scripts`, `yarn install --ignore-scripts`, `pnpm install --lockfile-only --ignore-scripts`, `bun install --lockfile-only`, `cargo update`, `poetry lock`. `--offline` or a failed refresh leaves the lock unchanged; later scans then trust the lockfile and say so
- Nested manifests below the scan root are included for Maven (`pom.xml`), Gradle (`build.gradle` / `build.gradle.kts`), npm (`package.json`), Cargo (`Cargo.toml`), and Python (`pyproject.toml`, `requirements.txt`). Root files stay parsed by the caller. `node_modules`, `target`, `build`, `dist`, `out`, `vendor`, and VCS/tool dirs are skipped
- Maven candidates with no OSV fixed version but an inclusive last-affected bound are promoted to the next published release after that bound. The last-affected version itself stays vulnerable and is never the target. Skipped when `--offline`
- Fix-loop re-scan overlay now reads Python direct deps (`pyproject.toml`, `requirements.txt`) and npm overrides, so a bumped manifest is visible before the lockfile moves

### Changed
- npm and Python bumps turn ceilings (`<`, `<=`) and a bare `>` into an inclusive floor (`>=`) so the fix version is admitted. Existing floors and exact pins keep their operator

### Fixed
- Direct-parse of Gradle excludes missed single-quoted `exclude group: '…', module: '…'` (the form gradle-editor writes, and idiomatic Groovy), so already-excluded coordinates were re-detected on every fresh session; both quote styles are now collected

## [0.0.1] - 2026-10-14

First release under the new name — rebranded from `@elephantseed/auto-depender`, with version numbering restarting at 0.0.1. Ships everything accumulated in the auto-depender lineage (July–October 2026):

### Added
- Local advisory vendoring for Maven advisories missing from the OSV bulk dump (e.g. vendor-published GHSA entries published after the last dump cut): `local-advisories/Maven.json` is loaded alongside the OSV database and matched by the same engine; ships CVE-2026-102554 (guava, fixed 33.7.2-jre) and CVE-2026-92877 (jaxb-core 4.x line, no fix released yet)
- `fix --latest` (Maven/Gradle): in addition to vulnerability-driven bumps, preemptively bumps every directly declared dependency to the newest non-prerelease available in the project's repositories (falling back to Maven Central). Prereleases and SNAPSHOTS are excluded, qualifier suffixes are preserved (`guava 33.6.0-jre` → `33.7.2-jre`), major bumps remain gated by `--allow-major`, and targets that cannot be resolved from the project repositories are rolled back automatically. Shared Gradle variables and pom properties are rewritten in place, so every dependency using them moves together
- Gradle direct-dep parser resolves version-concatenated declarations (`"group:artifact:" + versionVar`, e.g. `enforcedPlatform("...spring-cloud-dependencies:" + spring_cloud_version)`), so BOM/train imports declared that way are `--latest` candidates like any other direct dependency; unresolvable variables are still skipped
- `fix --apply` re-targets bumps whose target version cannot be resolved from the project repositories (e.g. yanked releases): after Gradle reports a `FAILED` tree node, auto-bumper queries the repository's `maven-metadata.xml` for the smallest available non-SNAPSHOT version above the failed one and bumps to that instead (`~ re-targeted … using X instead`)
- When no such version exists, the bump is rolled back — Gradle restores the exact declared version (downgrade-capable, which a normal bump cannot do) — and the fix is reported under "Skipped — target not resolvable" instead of leaving a broken build
- Manifest overlay on fix-loop re-scan (npm `package.json`, Rust `Cargo.toml` direct deps)
- Clear fix-loop stall messages when `--allow-major` / `--allow-renames` block progress
- `test/manifest-overlay.test.ts`
- Package rename detection for npm, PyPI, and crates.io from OSV advisories
- Manifest renames in `package.json`, `Cargo.toml`, `requirements.txt`, `pyproject.toml`
- Source migrations for JavaScript/TypeScript, Python, and Rust import lines
- Auto source rules derived from applied renames per ecosystem
- `--allow-source-migrations` — generic opt-in for source rewrites after coordinate renames (Java/Jackson today)
- `source-migrations.ts` orchestrator; migration clusters use `source.java` instead of top-level `java`
- Fix report **Planned source migrations** section in dry-run output
- TTY prompt for source migrations (third gate after major/rename)
- `--offline` flag on `scan` and `fix` — skip live OSV API queries; use cached advisory DB only
- Backup restore on `fix` apply failure and uncaught errors (manifests + Java import rewrites)
- GitHub Actions CI (`bun test`)
- `SECURITY.md` vulnerability reporting policy
- Jackson 3 coordinate migration support (`--allow-renames`)
- Opt-in Java import rewrites (`--allow-java-imports`)
- Gradle health warnings for mixed Maven groups and managed constraints

### Changed
- `fix --apply` re-scan cap defaults to 10 (`--max-iterations` to change)
- Rebranded from `@elephantseed/auto-depender` to `@elephantseed/auto-bumper`; version numbering restarts at 0.0.1
- Maven cross-major fixes on unchanged coordinates (e.g. guava `32.1.3-jre` → `33.7.2-jre`) are now planned as major bumps instead of being reported unfixable, and go through the same consent gate as npm (`--allow-major`, TTY prompt, skipped in dry-run/CI). Coordinate renames still take precedence when OSV provides them
- `--allow-java-imports` deprecated (still works as alias with stderr warning)
- Health warnings clarify manifest rename vs source rewrite scope
- README: ecosystem scope table for manifest rename vs source rewrite
- README: Bun required for `npx`/`bunx`, `--offline`, scan vs fix classpath, known limits
- `fix` documents `--allow-java-imports` for opt-in Java import rewrites with coordinate migrations

### Fixed
- `--exclude` packages were filtered only after scan summaries were computed, so excluded findings could still appear in reports; exclusion is now applied before counting and reporting
- Maven projects (Quarkus, Spring Boot) scanning as "No packages scanned" (0 packages): `mvn dependency:tree` ran with `-q`, which suppressed the whole tree (printed at INFO level); the direct-POM fallback then skipped every property-ref / parent-managed version. The tree is now parsed from normal output
- False positives on parallel release lines (Maven backports / LTS branches): a version at or above the fixed version of its own line (e.g. `netty-codec-haproxy` 4.1.138.Final carrying the 4.1-line backport) is no longer flagged just because another range's window numerically contains it; re-introductions (an introduced event above that fix) and explicit `versions` lists still flag
- Missed pgjdbc vulnerabilities (e.g. CVE-2026-107314 / CVE-2026-107315 in `org.postgresql:postgresql`, fixed 42.7.14): OSV publishes them as package-less NVD records, so they are absent from the Maven bulk dump; `pgjdbc/pgjdbc` is now in the default GHSA repo watchlist, so vendor-published advisories with proper Maven bindings are fetched and matched
- `scan`/`fix` invoked from outside the target project now resolve the cache (`.auto-bumper`) against the target project instead of the invocation directory — each working directory kept its own advisory cache, so a run from another folder could serve a stale one and report "No vulnerabilities found" while a scan from inside the project reported findings
- Maven `fix --apply` reported "0 direct, N constrained" for poms that declare versions via properties or literals in later `<dependency>` blocks: the block-matching regex was greedy and swallowed first-to-last `<dependency>`, so only the first block's coordinates were ever inspected — every bump fell back to a `dependencyManagement` pin, which is a silent no-op where the pom declares an explicit `<version>` (the installed version never moved). Dependency blocks are now parsed individually; property-backed bumps rewrite the shared `<properties>` value (max target when several artifacts share one property), literal bumps splice the exact block, and pins remain only for BOM-managed / parent-managed coordinates
- False positives from auto-derived OSV ranges over-covering vendor-backported lines (e.g. `jetty-http` 11.0.29 flagged for CVE-2024-6763 although the 11.x line was fixed in 11.0.27): for GHSA-keyed entries with a non-empty explicit `versions` list, the vendor-curated list is now authoritative and range matching is skipped; CVE-keyed records keep the union of list + ranges
- Maven pins for poms without a `<dependencyManagement>` section were inserted into top-level `<dependencies>`, declaring a real runtime dependency instead of managing a version; a `dependencyManagement` section is now created when missing
- Maven fixes pinning advisory "fixed" versions that do not exist in any project repository (vendor advisories claiming releases that were never published, e.g. `jetty-http` 11.0.29 / `jetty-security` 11.0.31 on the EOL 11.0.x line): each Maven target version is now validated against the repositories' `maven-metadata.xml` before applying, and unpublished targets are skipped (`~ skipped … not published in any project repository`) instead of producing a pom that strict Maven resolvers hard-fail on
- Maven scans silently ignored resolution failures: `mvn dependency:tree` exit status was discarded and lenient wrapper builds report BUILD SUCCESS even with missing POMs, so a bad pin looked resolved and the post-apply rollback (Gradle-only) never fired. Failed runs now extract the unresolvable coordinates ("could not be resolved" / "was not found in" lines) into `ParseResult.unresolved`, enabling the same rollback for Maven
- Missed jackson-coreutils vulnerabilities (CVE-2026-86321 / CVE-2026-86513 / CVE-2026-86511 in `com.github.java-json-tools:jackson-coreutils`): OSV publishes them as package-less NVD records with a GIT range only, and no vendor GHSA exists; the orphan-CVE bridge now covers the product via its repo signal, with curated CVE seeds (`knownCveIds`) for products that have no discoverable security page
- `fix` on Gradle projects scanned runtime classpath only, so test-scoped dependencies (e.g. rest-assured's transitive tree) were invisible to it while `scan` and IDE scanners flagged them; `fix` now scans runtime+test like `scan`
- `--exclude=group:artifact` only prevented bump application — excluded packages were still reported as findings and unfixable, so the tool's own "use --exclude to ignore" hint had no effect; excluded coordinates are now filtered from fix reports and the final verification scan
- `scan`/`fix` status output (⏳ progress, ✅ success lines) went to stderr, which terminals that colorize stderr render red even when nothing is wrong; informational spinner lines now go to stdout and only warnings (⚠️) and errors (❌) stay on stderr
- False positives from GitHub "Duplicate Advisory" mirror records (e.g. `tools.jackson.core:jackson-core` 3.1.7 flagged via GHSA-642r-3gj9-2pj5): mirrors whose affected packages are all bounded by fix data in non-duplicate records are dropped before matching; mirrors without such a boundary are kept (over-report rather than miss)
- Fix report miscount when a bump is applied via a managed constraint block (Gradle/Maven pins): constrained applications are now counted in `Applied N file change(s)` and listed in the `## Applied` table as `(constrained)` instead of being dropped from both
- Scan/fix banner states which Gradle configurations were counted when the scope is restricted (e.g. `fix` scans runtime classpath only, so its package count differs from a plain scan)
- Maven managed-pin block with multiple pins no longer loses all but the first pin on re-render (parser merged adjacent `<dependency>` elements)
- Orphan (package-less) OSV records for bridged products (Log4j) now detected in scans — `mapOsvVulnToAdvisory` enriches with bridged Maven coordinates and the scan pipeline merges the orphan cache
- `--offline` is strict on the DB-load path: a cached dump is used regardless of TTL instead of attempting a download
- Blocked fix-loop message reports source-bound renames (`N rename(s) need --allow-renames; K of them also need --allow-source-migrations`)
- Jackson 3 migration apply policy: old `com.fasterxml` coords excluded, `jackson-bom` removed, no pin for `tools.jackson.core:jackson-annotations`, `jackson-annotations` kept at 2.21
- JS/Python/Rust import editors actually rewrite again (broken backreference + corrupted regex escaping made them silent no-ops)
- Java package rewrites apply longest-prefix-first (`jsr310` → `tools.jackson.databind.ext.javatime`, not the generic rule)
- `fix C:\dev\...` no longer TypeErrors on Windows; prints forward-slash hint for mangled paths
- `--ecosystem=gradle` no longer returns false clean (0 packages) — Gradle tree uses maven coords + `build.gradle` manifest path
- `fix` on Gradle projects now scans with `--ecosystem=gradle` (was `maven`, same false clean)
- Scan/fix exit error when ecosystem filter matches zero packages
- Fix loop: plan-signature stall detection consolidated in `fixLoopStopReason`
- Fix loop: `lastAppliedCount` tracks actual file changes only
- Dedupe applied-bump reporting across loop passes
- `collectFixedVersions` now scopes fix versions to the matching `affected` package block (multi-package advisories)
- Jackson 3 migration keeps `jackson-annotations` 2.x on classpath; no exclude/rename for annotations coord
- Mixed-classpath Gradle projects always keep rename steps in fix plan
- Honest applied-bump reporting for bundled coordinate migrations
- Prefer same-major version bump when OSV lists both patch and major-coordinate fix

### Removed
- Live OSV `querybatch` API call — scans no longer send your package list to api.osv.dev. All detection runs against the local OSV database (ecosystem dumps + orphan-CVE bridge + vendor GHSA cache); keep it fresh with `bun cli/update-db.ts` or any online scan (public-data GETs only, nothing about your project is transmitted)
- `(+N from OSV API)` scan output note and the now-dead live-alias-merge code path
