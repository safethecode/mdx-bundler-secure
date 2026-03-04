<div align="center">
<h1>mdx-bundler-secure</h1>

<p>Security-hardened fork of <a href="https://github.com/kentcdodds/mdx-bundler">mdx-bundler</a>. Compile and bundle your MDX files and their dependencies. FAST.</p>
</div>

---

[![version][version-badge]][package]
[![downloads][downloads-badge]][npmtrends]
[![MIT License][license-badge]][license]

## Why this fork?

[CVE-2026-0969](https://nvd.nist.gov/vuln/detail/CVE-2026-0969) disclosed a high-severity **arbitrary code execution** vulnerability in server-side MDX rendering. The original `mdx-bundler` is confirmed affected but has no patch. `mdx-bundler-secure` is a **drop-in replacement** that adds multi-layer RCE mitigation while keeping full backward compatibility.

### What was the vulnerability?

MDX allows JavaScript expressions inside `{curly braces}`. When untrusted MDX is compiled and evaluated server-side, an attacker can inject:

```mdx
{require('child_process').execSync('cat /etc/passwd')}
{eval("process.exit(1)")}
{new Function("return process.env")()}
```

These execute with **full Node.js privileges** on your server.

### How does this fork fix it?

Three defence layers:

| Layer | What it does | Default |
|---|---|---|
| `blockDangerousJS` | Remark plugin blocks known dangerous patterns (`eval`, `require`, `process`, `Function`, `import()`, `__proto__`, etc.) and imports from Node.js built-in modules (`child_process`, `fs`, `vm`, ...) | `true` |
| `blockJS` | Remark plugin strips **all** `{expressions}` from MDX before compilation | `false` |
| Runtime shadow | `getMDXExport` shadows `eval`, `Function`, `process`, `global`, `globalThis`, `__dirname`, `__filename` as `undefined` in the `new Function()` scope | Always on |

## Migrating from mdx-bundler

```diff
- npm install mdx-bundler
+ npm install mdx-bundler-secure
```

```diff
- import {bundleMDX} from 'mdx-bundler'
+ import {bundleMDX} from 'mdx-bundler-secure'

- import {getMDXComponent} from 'mdx-bundler/client'
+ import {getMDXComponent} from 'mdx-bundler-secure/client'
```

That's it. All existing MDX content with safe expressions (`{title}`, `{frontmatter.date}`, `{items.map(...)}`, etc.) works without changes.

## Installation

```
npm install mdx-bundler-secure esbuild
```

One of mdx-bundler-secure's dependencies requires a working [node-gyp][node-gyp] setup to be able to install correctly.

## Usage

```typescript
import {bundleMDX} from 'mdx-bundler-secure'

const mdxSource = `
---
title: Example Post
published: 2021-02-13
description: This is some description
---

# Wahoo

import Demo from './demo'

Here's a **neat** demo:

<Demo />
`.trim()

const result = await bundleMDX({
  source: mdxSource,
  files: {
    './demo.tsx': `
import * as React from 'react'

function Demo() {
  return <div>Neat demo!</div>
}

export default Demo
    `,
  },
})

const {code, frontmatter} = result
```

From there, you send the `code` to your client, and then:

```jsx
import * as React from 'react'
import {getMDXComponent} from 'mdx-bundler-secure/client'

function Post({code, frontmatter}) {
  const Component = React.useMemo(() => getMDXComponent(code), [code])
  return (
    <>
      <header>
        <h1>{frontmatter.title}</h1>
        <p>{frontmatter.description}</p>
      </header>
      <main>
        <Component />
      </main>
    </>
  )
}
```

### Security Options

#### blockDangerousJS

Type: `boolean` | Default: `true`

Best-effort check that blocks known dangerous JavaScript patterns in MDX expressions and imports from dangerous Node.js built-in modules. Safe expressions like `{title}` or `{items.map(x => x.name)}` pass through.

**Blocked patterns include:** `eval()`, `Function()`, `new Function()`, `require()`, `import()`, `process.*`, `global`, `globalThis`, `__dirname`, `__filename`, `__proto__`, `.constructor[`, `setTimeout("string", ...)`, `Object.getPrototypeOf`

**Blocked modules include:** `child_process`, `fs`, `net`, `os`, `vm`, `worker_threads`, `http`, `https`, and all `node:*` prefixed imports.

```js
// Default: dangerous patterns are blocked
const result = await bundleMDX({source: mdxSource})

// Opt out for fully trusted content
const result = await bundleMDX({
  source: trustedMdxSource,
  blockDangerousJS: false,
})
```

#### blockJS

Type: `boolean` | Default: `false`

Strips **all** JavaScript expressions (`{...}`) from MDX before compilation. This is the strongest protection for rendering completely untrusted user-generated MDX.

```js
const result = await bundleMDX({
  source: userSuppliedMdx,
  blockJS: true, // removes all {expressions}, only static markdown remains
})
```

When both `blockJS` and `blockDangerousJS` are `true`, `blockJS` takes precedence (strips all rather than throwing on dangerous ones).

### Options

#### source

The `string` source of your MDX.

_Can not be set if `file` is set_

#### file

The path to the file on your disk with the MDX in. You will probably want to set [cwd](#cwd) as well.

_Can not be set if `source` is set_

#### files

The `files` config is an object of all the files you're bundling. The key is the path to the file (relative to the MDX source) and the value is the string of the file source code. You could get these from the filesystem or from a remote database. If your MDX doesn't reference other files (or only imports things from `node_modules`), then you can omit this entirely.

#### mdxOptions

This allows you to modify the built-in MDX configuration (passed to `@mdx-js/esbuild`). This can be helpful for specifying your own remarkPlugins/rehypePlugins.

The function is passed the default mdxOptions and the frontmatter.

```ts
bundleMDX({
  source: mdxSource,
  mdxOptions(options, frontmatter) {
    options.remarkPlugins = [...(options.remarkPlugins ?? []), myRemarkPlugin]
    options.rehypePlugins = [...(options.rehypePlugins ?? []), myRehypePlugin]

    return options
  },
})
```

#### esbuildOptions

You can customize any of esbuild options with the option `esbuildOptions`. This takes a function which is passed the default esbuild options and the frontmatter and expects an options object to be returned.

```typescript
bundleMDX({
  source: mdxSource,
  esbuildOptions(options, frontmatter) {
    options.minify = false
    options.target = [
      'es2020',
      'chrome58',
      'firefox57',
      'safari11',
      'edge16',
      'node12',
    ]

    return options
  },
})
```

More information on the available options can be found in the [esbuild documentation](https://esbuild.github.io/api/#build-api).

#### globals

This tells esbuild that a given module is externally available. For example, if your MDX file uses the d3 library and you're already using the d3 library in your app then you'll end up shipping `d3` to the user twice (once for your app and once for this MDX component). This is wasteful and you'd be better off just telling esbuild to _not_ bundle `d3` and you can pass it to the component yourself when you call `getMDXComponent`.

```tsx
// server-side or build-time code that runs in Node:
import {bundleMDX} from 'mdx-bundler-secure'

const mdxSource = `
# This is the title

import leftPad from 'left-pad'

<div>{leftPad("Neat demo!", 12, '!')}</div>
`.trim()

const result = await bundleMDX({
  source: mdxSource,
  globals: {'left-pad': 'myLeftPad'},
})
```

```tsx
// server-rendered and/or client-side code that can run in the browser or Node:
import * as React from 'react'
import leftPad from 'left-pad'
import {getMDXComponent} from 'mdx-bundler-secure/client'

function MDXPage({code}: {code: string}) {
  const Component = React.useMemo(
    () => getMDXComponent(result.code, {myLeftPad: leftPad}),
    [result.code, leftPad],
  )
  return (
    <main>
      <Component />
    </main>
  )
}
```

#### cwd

Setting `cwd` (_current working directory_) to a directory will allow esbuild to resolve imports. This directory could be the directory the mdx content was read from or a directory that off-disk mdx should be _run_ in.

#### grayMatterOptions

This allows you to configure the [gray-matter options](https://github.com/jonschlinkert/gray-matter#options).

```js
bundleMDX({
  grayMatterOptions: options => {
    options.excerpt = true
    return options
  },
})
```

#### bundleDirectory & bundlePath

This allows you to set the output directory for the bundle and the public URL to the directory. If one option is set the other must be as well.

#### jsxConfig

Allows output for JSX runtimes other than React (Preact, Hono, Vue, etc). See [Other JSX runtimes](#other-jsx-runtimes).

### Returns

`bundleMDX` returns a promise for an object with the following properties.

- `code` - The bundle of your mdx as a `string`.
- `frontmatter` - The frontmatter `object` from gray-matter.
- `matter` - The whole [object returned by gray-matter](https://github.com/jonschlinkert/gray-matter#returned-object)

### Types

`mdx-bundler-secure` supplies complete typings within its own package.

`bundleMDX` has a single type parameter which is the type of your frontmatter. It defaults to `{[key: string]: any}` and must be an object.

```ts
const {frontmatter} = bundleMDX<{title: string}>({source})

frontmatter.title // has type string
```

### Component Substitution

MDX Bundler passes on [MDX's ability to substitute components](https://mdxjs.com/docs/using-mdx/#components) through the `components` prop on the component returned by `getMDXComponent`.

```tsx
import * as React from 'react'
import {getMDXComponent} from 'mdx-bundler-secure/client'

const Paragraph: React.FC = props => {
  if (typeof props.children !== 'string' && props.children.type === 'img') {
    return <>{props.children}</>
  }

  return <p {...props} />
}

function MDXPage({code}: {code: string}) {
  const Component = React.useMemo(() => getMDXComponent(code), [code])

  return (
    <main>
      <Component components={{p: Paragraph}} />
    </main>
  )
}
```

### Frontmatter and const

You can reference frontmatter meta or consts in the mdx content.

```mdx
---
title: Example Post
---

export const exampleImage = 'https://example.com/image.jpg'

# {frontmatter.title}

<img src={exampleImage} alt="Image alt text" />
```

### Accessing named exports

You can use `getMDXExport` instead of `getMDXComponent` to treat the mdx file as a module instead of just a component. It takes the same arguments that `getMDXComponent` does.

```js
import * as React from 'react'
import {getMDXExport} from 'mdx-bundler-secure/client'

function MDXPage({code}: {code: string}) {
  const mdxExport = getMDXExport(code)
  console.log(mdxExport.toc) // [ { depth: 1, value: 'The title' } ]

  const Component = React.useMemo(() => mdxExport.default, [code])

  return <Component />
}
```

### Other JSX runtimes

JSX runtimes mentioned [here](https://mdxjs.com/docs/getting-started/#jsx) are guaranteed to be supported. Any JSX runtime with its own jsx runtime export should work.

```tsx
const getMDX = (source) => {
  return bundleMDX({
    source,
    jsxConfig: {
      jsxLib: {
        varName: 'HonoJSX',
        package: 'hono/jsx',
      },
      jsxDom: {
        varName: 'HonoDOM',
        package: 'hono/jsx/dom',
      },
      jsxRuntime: {
        varName: '_jsx_runtime',
        package: 'hono/jsx/jsx-runtime',
      },
    }
  });
}

// Client side
import { getMDXComponent } from "mdx-bundler-secure/client/jsx";
import * as HonoJSX from "hono/jsx";
import * as HonoDOM from "hono/jsx/dom";
import * as _jsx_runtime from "hono/jsx/jsx-runtime";

const Component = getMDXComponent(code, { HonoJSX, HonoDOM, _jsx_runtime });
```

### Known Issues

#### Cloudflare Workers

Workers can't run binaries (`esbuild`) or `eval`/`new Function`. See the [original repo](https://github.com/kentcdodds/mdx-bundler#cloudflare-workers) for workarounds.

#### Next.JS esbuild ENOENT

esbuild relies on `__dirname` to find its executable. Adding the following before `bundleMDX` fixes this:

```js
import path from 'path'

if (process.platform === 'win32') {
  process.env.ESBUILD_BINARY_PATH = path.join(
    process.cwd(), 'node_modules', 'esbuild', 'esbuild.exe',
  )
} else {
  process.env.ESBUILD_BINARY_PATH = path.join(
    process.cwd(), 'node_modules', 'esbuild', 'bin', 'esbuild',
  )
}
```

## Credits

Original [mdx-bundler](https://github.com/kentcdodds/mdx-bundler) by [Kent C. Dodds](https://kentcdodds.com) and [contributors](https://github.com/kentcdodds/mdx-bundler#contributors-).

## LICENSE

MIT

<!-- prettier-ignore-start -->
[version-badge]: https://img.shields.io/npm/v/mdx-bundler-secure.svg?style=flat-square
[package]: https://www.npmjs.com/package/mdx-bundler-secure
[downloads-badge]: https://img.shields.io/npm/dm/mdx-bundler-secure.svg?style=flat-square
[npmtrends]: https://www.npmtrends.com/mdx-bundler-secure
[license-badge]: https://img.shields.io/npm/l/mdx-bundler-secure.svg?style=flat-square
[license]: https://github.com/safethecode/mdx-bundler-secure/blob/main/LICENSE
[node-gyp]: https://github.com/nodejs/node-gyp#installation
<!-- prettier-ignore-end -->
