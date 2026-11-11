# Security

MDX compiles to JavaScript and executes with the privileges of the process that
evaluates the generated code. Treat MDX, imported files, plugins, JSX components,
custom frontmatter engines, and supplied globals as trusted code.

`blockDangerousJS` is a best-effort check for known dangerous patterns.
`blockJS` also removes source imports/exports, expressions, and dynamic JSX
attributes, but retains static JSX and generated frontmatter exports. Neither
option sanitizes HTML or provides an execution sandbox. For untrusted content,
use a Markdown renderer without JavaScript execution or an isolated environment
with restricted privileges and resource limits.

Version 2 rejects JavaScript frontmatter before the MDX plugins run, uses patched
data parsers, and requires Node.js 22+ and esbuild 0.25.0+. Keep the host runtime,
esbuild peer, UI runtime, and your application's dependencies patched as well.

The [2026-11-11 review](https://github.com/safethecode/mdx-bundler-secure/blob/main/other/security-review.md) records the reviewed advisories
and the scope of dependency verification. A clean audit describes the known
advisories for the resolved dependency tree at that time; it is not a guarantee
against all vulnerabilities or a review of downstream applications.

Report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/safethecode/mdx-bundler-secure/security/advisories/new).
