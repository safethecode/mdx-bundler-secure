# mdx-bundler-secure

Markdown and a restricted, static subset of MDX with a data-only default.
An explicit trusted mode retains the original MDX/TSX bundler.

Version 3 closes the execution, import, and HTML boundaries left open by the
best-effort filters in 2.x. **Upgrading from 2.x requires rebuilding stored
artifacts and updating trusted-mode call sites.**

## Install

```sh
npm install mdx-bundler-secure@3 esbuild
```

Requires Node.js 22+, npm 10+, and esbuild `>=0.25.0 <1`.

## Default: strict content

```js
import {bundleMDX} from 'mdx-bundler-secure'

const {code, frontmatter} = await bundleMDX({
  source: `---
title: My post
---
# {frontmatter.title}

A **strong** word and <span title="static">static JSX</span>.
`,
})
```

Render with the matching client:

```jsx
import {useMemo} from 'react'
import {getMDXComponent} from 'mdx-bundler-secure/client'

export function Post({code}) {
  const Content = useMemo(() => getMDXComponent(code), [code])
  return <Content />
}
```

Strict `code` is a versioned data artifact. The client validates the artifact and
constructs elements directly; it does not use `eval` or `new Function`.

Strict mode supports:

- Markdown headings, lists, links, images, quotes, code blocks, and inline code.
- Static JSX using a fixed list of content elements, attributes, and URL schemes.
- YAML, JSON, and TOML frontmatter (`---`, `---json`, and `+++`).
- Literal values and own frontmatter property references such as
  `{frontmatter.title}` or `{frontmatter['title']}`. Calls, functions, operators,
  arbitrary identifiers, and prototype properties are rejected.
- `blockJS: true` to remove expressions, dynamic JSX attributes, and source
  imports/exports entirely. The element/attribute/URL policy remains active.

Strict mode rejects source imports and exports by default and never resolves
source modules or packages. It does not run caller plugins or custom engines.
`files`, `globals`, `mdxOptions`, `esbuildOptions`, `grayMatterOptions`,
`jsxConfig`, `bundleDirectory`, and `bundlePath` require trusted mode.

The static policy rejects scripts, iframes, SVG/MathML, forms, embedded objects,
inline styles, event handlers, raw HTML insertion, and unsafe URL protocols.
Element IDs and fragment links receive the `mdx-content-` prefix. New-window links
receive `noopener noreferrer`. Unknown elements and attributes fail closed.

Host-provided `components` mappings remain available for styling Markdown tags.
Those components are application code: they and the JSX runtime must be trusted.
Never obtain component implementations or security options from an untrusted
request body.

## Explicit file input

```js
const result = await bundleMDX({file: 'post.mdx', cwd: '/srv/content'})
```

Strict mode opens only `.md` and `.mdx` entry files whose real paths are inside
`cwd` (default: `process.cwd()`). Imports inside the content are still rejected.
The application controls entry paths and should keep the content directory
read-only to untrusted users.

## Resource limits

Strict parsing runs in a disposable worker with a deadline and V8 heap limits.
The source is never evaluated in that worker.

| Limit                               | Default / ceiling         |
| ----------------------------------- | ------------------------- |
| UTF-8 source                        | 256 KiB                   |
| Static artifact                     | 2 MiB                     |
| Data / tree nodes                   | 10,000                    |
| Data / tree depth                   | 64                        |
| Parser queue and execution deadline | 5,000 ms                  |
| Active workers / pending jobs       | 2 / 8 per module instance |
| Worker V8 old / young heap          | 64 / 16 MiB               |

Applications can lower the configurable limits:

```js
await bundleMDX({
  source,
  securityLimits: {
    maxSourceBytes: 128 * 1024,
    maxNodes: 5000,
    maxDepth: 32,
    timeoutMs: 3000,
  },
})
```

Limits must be positive integers and cannot exceed the built-in ceilings.
Overloaded queues, worker failures, and deadline expiry reject the operation.
These are parser resource controls, not an OS sandbox or a total process-memory
guarantee. Apply request-size limits, rate limiting, and service-wide resource
controls as well. `securityLimits` does not apply to trusted mode.

Keep the server package external when bundling a Node server so its worker files
remain available. The `client` entry points can be bundled for the browser and
do not import Node worker or filesystem modules.

## Trusted MDX and module bundling

Use this mode only for code whose authors and dependencies you trust with the
application's privileges. Both compilation and client evaluation require an
explicit opt-in:

```js
const {code} = await bundleMDX({
  trusted: true,
  source: `import Demo from './demo'

<Demo />`,
  files: {
    './demo.jsx': 'export default () => <strong>Trusted component</strong>',
  },
})

const Content = getMDXComponent(code, undefined, {trusted: true})
```

The original compiler options, module bundling, named exports, and framework
configuration are available in trusted mode. Its legacy `blockDangerousJS`
(default `true`) and `blockJS` filters are best-effort utilities, not execution or
HTML security boundaries. Trusted code runs with application privileges and is
not subject to the strict parser limits. Do not mark externally authored MDX as
trusted to work around a validation error.

## Client API

```js
// React
getMDXComponent(code, globals?, options?)
getMDXExport(code, globals?, options?)

// Other JSX runtimes: mdx-bundler-secure/client/jsx
getMDXComponent(code, jsxGlobals, globals?, options?)
getMDXExport(code, jsxGlobals, globals?, options?)
```

`options.trusted` defaults to `false`. Without it, executable JavaScript strings
(including old 2.x output) are rejected before evaluation. Static artifacts are
validated even when a caller has enabled trusted evaluation. `globals` is not
accepted for static artifacts. For another JSX runtime, supply its
`_jsx_runtime` in `jsxGlobals`; static artifacts are framework-independent.

`getMDXExport` returns `{default, frontmatter}` for strict content. Source-defined
named exports require trusted mode. Strict frontmatter artifacts contain plain
JSON data; dates are serialized and YAML aliases do not preserve object identity.
The returned server `frontmatter` retains supported Date values.

## Migration from 2.x

1. Rebuild stored `code` strings using 3.x and deploy matching 3.x clients.
2. Keep untrusted content in the default strict mode. Replace executable
   expressions with frontmatter values or plain Markdown.
3. For application-owned MDX that needs full JavaScript, imports, or plugins,
   explicitly set `trusted: true` at both compiler and client call sites.
4. Pass security options, paths, plugins, globals, and host components from trusted
   application code. Do not spread untrusted request objects into these APIs.
5. Transport artifacts as JSON using your framework's escaping rules, not raw HTML.

Run `npm ci` and `npm run validate` for lint, type checks, strict/trusted tests,
build, consumer declarations, packaged runtime checks, and the dependency audit.
See [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

MIT. Based on [mdx-bundler](https://github.com/kentcdodds/mdx-bundler).
