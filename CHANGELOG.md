# CHANGELOG

## 3.0.0

### Security

- Make strict, data-only content the default. Interpret a small literal and own
  frontmatter-reference syntax; reject executable syntax and source modules.
- Render validated static artifacts directly in the client. Raw JavaScript
  requires a separate explicit trusted opt-in at both compiler and client.
- Enforce an element, attribute, and URL allowlist at compilation and client
  decoding. Reject scripts, embedded documents, inline styles, event handlers,
  raw HTML insertion, and unsafe URL schemes, including with `blockJS: true`.
- Remove filesystem/package resolution from strict content. Restrict explicit
  Markdown entry files to real paths inside the caller's `cwd`.
- Bound parsing with disposable workers, deadlines, V8 heap limits, source and
  artifact byte limits, node/depth budgets, and a bounded concurrency queue.
- Add strict/trusted boundary, resource-limit, client artifact, file-path, and
  cross-runtime regression coverage. Known unsafe inputs are tested as rejected
  data, without executing them.

### Breaking changes

- Strict `code` is a versioned data artifact. Rebuild 2.x artifacts and deploy
  matching 3.x clients. Direct evaluation of old JavaScript output is rejected.
- Full MDX programs, imports, custom components named by content, plugins, custom
  frontmatter engines, globals, and esbuild options require `trusted: true`.
  Trusted mode retains application privileges and is not sandboxed.
- Trusted evaluation requires `getMDXComponent(code, globals, {trusted: true})`
  or the corresponding export/JSX client signature.
- Strict source size, parsing deadlines, data depth, node count, and accepted HTML
  are limited. Strict metadata artifacts contain plain JSON data and do not
  preserve YAML alias identity. Element IDs and fragment links are namespaced.

See [the 3.x security review](https://github.com/safethecode/mdx-bundler-secure/blob/main/other/security-review-v3.md)
and the migration guide in README.md.

## 2.0.0

### Security

- Replace `uuid` with Node.js `crypto.randomUUID()`, removing the dependency
  affected by CVE-2026-41907.
- Upgrade `remark-mdx-frontmatter` to 6.0.0 and remove `toml`, including
  CVE-2026-114144 and related parser denial-of-service/prototype-pollution issues.
- Require patched parsers: `js-yaml` 3.15.2+, `yaml` 2.9.1+, and `smol-toml` 1.9.1+.
- Reject executable JavaScript frontmatter before parsing MDX.
- Strip source imports/exports and dynamic JSX attributes in `blockJS` mode.
- Check dangerous code in module statements and block dangerous built-in subpaths
  and the `module` loader.
- Update test runtimes and replace the unused `kcd-scripts` dependency tree with
  direct build, lint, and typecheck tools. Patch development glob/minimatch paths.
- Commit the dependency lockfile and enforce full dependency audits in validation.
- Verify generated declarations with strict NodeNext consumer checks and repair
  public type imports that were not exported by their dependencies.

### Breaking changes

- Require Node.js 22+ and npm 10+; `remark-mdx-frontmatter` 6 no longer supports
  Node.js 18 or 20.
- Require a patched esbuild peer (`>=0.25.0 <1`).
- JavaScript frontmatter is disabled, and `blockJS: true` now removes source ESM.

See the [security review](https://github.com/safethecode/mdx-bundler-secure/blob/main/other/security-review.md) for scope, affected paths, and
the limits of the MDX security options.

## 1.0.0

Initial security-hardened fork of mdx-bundler.
