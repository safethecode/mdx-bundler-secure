# Security review — 2026-11-11

This is the historical dependency and filter review for 2.0.0. Its clean
dependency audit did not establish an execution or HTML isolation boundary.
The [3.x boundary review](security-review-v3.md) documents the replacement of
those defaults with a data-only content path.

Release: **2.0.0**. Baseline commit:
`a5d2e6ff35950ddf02ab8164f83f798bdee307f3` (npm 1.0.0).

## Scope and evidence

Reviewed the complete resolved npm dependency tree, including development tools,
the esbuild peer, frontmatter parsing, MDX expression/module filtering, and the
built CommonJS/client distribution. Compared npm's audit findings with GitHub's
reviewed advisories, including related MDX and React Server Components issues
published in 2026. The [advisory inventory](security-advisories.json) records all
78 reviewed advisory IDs, CVE IDs, affected ranges, fixes, and source URLs.

The original repository had no dependency lockfile. The baseline is a fresh
resolution of the 1.0.0 manifest, rather than an assertion about every previous
consumer installation. Its 31 affected package entries represented 62 distinct
advisories; transitive advisory propagation accounts for the different counts.

| Audit                          | Critical | High | Moderate | Low | Total affected package entries |
| ------------------------------ | -------: | ---: | -------: | --: | -----------------------------: |
| Baseline, full dependency tree |        0 |   13 |       10 |   8 |                             31 |
| 2.0.0, full dependency tree    |        0 |    0 |        0 |   0 |                              0 |
| 2.0.0, production dependencies |        0 |    0 |        0 |   0 |                              0 |

These results describe known advisories on the review date. They do not establish
that arbitrary MDX is safe to execute or audit downstream applications.

## Dependency findings

| Dependency / advisory                                                                                                                                                                                                                                                                                                                                                       | Impact on this package                                                                                                                                                     | Resolution                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uuid`, [CVE-2026-41907](https://github.com/advisories/GHSA-w5hq-g745-h8pq)                                                                                                                                                                                                                                                                                                 | The 9.x dependency is in the affected range. This package called `v4()` without a buffer, so the reported v3/v5/v6 bounds defect was not exercised by its UUID call sites. | Remove `uuid` and its types; use `node:crypto.randomUUID()` for temporary entry names.                                                                     |
| `toml`, [CVE-2026-114144](https://github.com/advisories/GHSA-9qmh-m7c6-f92p) and five related parser advisories                                                                                                                                                                                                                                                             | Pulled in by `remark-mdx-frontmatter` 4. The affected parser handles TOML when enabled in the MDX options.                                                                 | Upgrade the plugin to 6.0.0, remove `toml`, and explicitly supply `smol-toml` 1.9.1 in the frontmatter paths.                                              |
| `smol-toml`, [GHSA-r4xh-jqrq-34v2](https://github.com/advisories/GHSA-r4xh-jqrq-34v2), [CVE-2026-85730](https://github.com/advisories/GHSA-7w5x-hrqm-74c2), and earlier resource-exhaustion advisories                                                                                                                                                                      | A parser migration alone could still select affected older versions allowed by the plugin's broad range.                                                                   | Declare a 1.9.1 minimum and use that parser explicitly.                                                                                                    |
| `js-yaml`, [CVE-2026-84375](https://github.com/advisories/GHSA-2883-xcg3-v3hh), [CVE-2026-59869](https://github.com/advisories/GHSA-52cp-r559-cp3m), [CVE-2026-53550](https://github.com/advisories/GHSA-h67p-54hq-rp68), [CVE-2025-64718](https://github.com/advisories/GHSA-mh29-5h37-fv8m), and [GHSA-5p4m-2wfm-xmqj](https://github.com/advisories/GHSA-5p4m-2wfm-xmqj) | `gray-matter`'s broad dependency range permits older YAML parsers. A fresh baseline already selected a patched parser; existing consumer locks may differ.                 | Require `js-yaml` 3.15.2 and explicitly use its safe loader, preserving returned YAML date behavior.                                                       |
| `yaml`, [CVE-2026-33532](https://github.com/advisories/GHSA-48c2-rrv3-qjmp)                                                                                                                                                                                                                                                                                                 | The MDX frontmatter plugin's broad range permits affected YAML versions.                                                                                                   | Require and explicitly use `yaml` 2.9.1 for generated exports, preserving string dates and YAML aliases.                                                   |
| esbuild, [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99)                                                                                                                                                                                                                                                                                           | The old development version and unrestricted peer range allowed affected releases. This library uses `build()`, not the vulnerable development server API.                 | Develop with 0.28.2 and require a peer version of at least 0.25.0.                                                                                         |
| Hono and Vue / `@vue/server-renderer` advisories                                                                                                                                                                                                                                                                                                                            | Test dependencies, including JSX rendering issues; these are not shipped as this package's runtime dependencies.                                                           | Update Hono to 4.13.17 and Vue to 3.5.45; retain runtime integration tests. Consumers selecting these JSX runtimes must update their own dependencies too. |
| `kcd-scripts`, serialization, pattern matching, and other build/test dependencies                                                                                                                                                                                                                                                                                           | Development-only paths inflated the dependency tree and pulled in unmaintained vulnerable tooling.                                                                         | Replace `kcd-scripts` with direct esbuild, TypeScript, and ESLint commands; update coverage tools and use patched glob/minimatch overrides.                |

The published manifest declares the patched parsers as direct dependencies and
uses them explicitly. Root overrides and a library's own lockfile do not force
transitive versions in downstream installations; the overrides here protect the
repository's development tooling. Consumers should regenerate or update their
own lockfiles and run their own audits.

## Local code findings and fixes

- **Executable frontmatter ran before expression checks.** `gray-matter` supports
  JavaScript frontmatter engines. Reject both `js` and `javascript`, including
  case aliases, before parsing string, VFile, or file input. This check remains
  active when expression filtering is disabled.
- **`blockJS` left source module code executable.** Remove source ESM imports and
  exports as well as expression nodes. Preserve data exports generated by the
  frontmatter plugin. Remove expression-valued JSX attributes instead of turning
  them into boolean attributes; remove spread attributes too.
- **Dangerous code in exported declarations was not checked.** Apply existing
  dangerous-pattern checks to source module statements.
- **Module matching missed subpaths and obfuscated imports.** Reject dangerous
  built-in subpaths and the `module` loader. Read decoded import/re-export
  specifiers from ESTree so comments and escaped module names do not hide them.

These local findings are code-review results, not newly assigned CVE IDs.

## Related advisories outside the dependency tree

[CVE-2026-0969](https://github.com/advisories/GHSA-g4xw-jxrg-5f6m) names
`next-mdx-remote`, which is absent from this package's dependencies. The general
risk of executing untrusted MDX is relevant to this package too. Expression
filters and shadowed globals do not make JavaScript evaluation a sandbox.

The recent React Server Components RCE,
[CVE-2026-126187](https://github.com/advisories/GHSA-xqc2-xf4c-x3h3) (GitHub
Advisory Database publication: 2026-11-10), and the other reviewed 2026 RSC
advisories affect `react-server-dom-*` packages. None are present in this
dependency tree. A consuming application's RSC framework must be checked
independently; updating this library cannot patch that application's framework.

## Verification and maintenance

Local verification passed all 80 tests, lint, type checking, build, and both
dependency audits. A fresh tarball installation in an empty consumer project
passed CommonJS/ESM/client runtime checks, strict NodeNext declaration checking
with `skipLibCheck: false`, and an audit with the minimum esbuild peer (0.25.0).

- Run `npm ci` using the committed lockfile.
- Run `npm run validate`: lint, typecheck, source/security/runtime tests, build,
  CommonJS/ESM/client smoke checks, and the full dependency audit.
- Run `npm audit --omit=dev` and check `npm ls uuid toml --all` for removed packages.
- Inspect the tarball and test a clean consumer installation, including the
  minimum supported esbuild peer and TypeScript declarations.
- CI repeats validation on Node.js 22, 24, and 26 before publishing a version tag.

Version 2 requires Node.js 22+, npm 10+, and esbuild 0.25.0+. This is a major
release because Node.js support, JavaScript frontmatter, and `blockJS` module
behavior changed. See [SECURITY.md](../SECURITY.md) for the trust boundary.
