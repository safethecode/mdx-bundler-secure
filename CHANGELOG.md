# CHANGELOG

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
