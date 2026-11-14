# Security

## Strict default in 3.x

The default compiler accepts a restricted Markdown/static-MDX data format. It
parses syntax in a bounded worker, interprets only literal data and own
frontmatter references, rejects source imports/exports, and emits a versioned
JSON artifact instead of executable JavaScript. The client checks the artifact's
schema, depth, node/byte budget, tags, attributes, and URL protocols before
constructing elements. It does not evaluate the artifact as JavaScript.

Scripts, embedded documents, SVG/MathML, forms, inline styles, event attributes,
raw HTML insertion, and arbitrary components named by the content are not part
of this format. `blockJS: true` also removes expressions, source module
statements, and dynamic attributes; it does not disable the static HTML policy.

The parser has input/output, node, depth, queue, V8 heap, and deadline controls.
A worker deadline terminates the worker before rejecting the compilation.
Worker heap limits do not bound all native allocations or guarantee the memory
use of the whole service. Workers are resource-isolation tools, not OS security
sandboxes. Public services also need request-size limits, rate limiting,
concurrency controls, and OS/container resource limits appropriate to their load.

Explicit entry files are restricted by their real paths to the application-owned
`cwd`, and only `.md` / `.mdx` files are opened. Strict content cannot request
additional filesystem access. Keep that content root read-only to untrusted
users. Entry file paths and security configuration are controlled by the host.

## Trusted mode is application code

`trusted: true` enables the legacy executable MDX compiler with application
privileges. A separate `{trusted: true}` client option is required to evaluate
its JavaScript output. The legacy pattern checks and shadowed globals are not a
sandbox. Strict parsing limits and static HTML restrictions do not cover this
mode. Never use it for untrusted authors, uploaded modules, or request-supplied
plugins, engines, globals, and code.

JSX runtime functions and host `components` implementations are trusted
application code in either mode. Do not derive them, the trusted opt-in, paths,
or compiler configuration from an untrusted request object. Transport the code
artifact as escaped JSON rather than inserting it as raw HTML.

## Dependencies and versions

Use 3.x for the strict defaults. The 2.x filters do not provide the 3.x data-only
boundary. Dependency audits cover advisories for the resolved tree on the audit
date; a clean audit does not prove the absence of code-level defects or audit a
consuming application's framework. Keep Node.js, esbuild, and UI runtimes patched.

Report suspected vulnerabilities privately through
[GitHub security advisories](https://github.com/safethecode/mdx-bundler-secure/security/advisories/new).
