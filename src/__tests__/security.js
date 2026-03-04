import './setup-tests.js'
import {suite} from 'uvu'
import * as assert from 'uvu/assert'
import React from 'react'
import rtl from '@testing-library/react'
import {bundleMDX} from '../index.js'
import {getMDXComponent, getMDXExport} from '../client/react.js'
import {
  matchesDangerousPattern,
  isDangerousModule,
  DANGEROUS_GLOBALS_SHADOW,
} from '../security.js'

const {render} = rtl

// ===================================================================
// Unit tests – pattern matching helpers
// ===================================================================

const patterns = suite('matchesDangerousPattern')

patterns('detects eval()', () => {
  assert.ok(matchesDangerousPattern('eval("code")').matched)
  assert.ok(matchesDangerousPattern('eval ("code")').matched)
  assert.ok(matchesDangerousPattern('window.eval("x")').matched)
})

patterns('detects Function constructor', () => {
  assert.ok(matchesDangerousPattern('Function("return this")').matched)
  assert.ok(matchesDangerousPattern('new Function("code")').matched)
  assert.ok(matchesDangerousPattern('new  Function("code")').matched)
})

patterns('detects process access', () => {
  assert.ok(matchesDangerousPattern('process.env.SECRET').matched)
  assert.ok(matchesDangerousPattern('process.exit(1)').matched)
  assert.ok(matchesDangerousPattern('process["env"]').matched)
})

patterns('detects require()', () => {
  assert.ok(matchesDangerousPattern("require('child_process')").matched)
  assert.ok(matchesDangerousPattern('require("fs")').matched)
  assert.ok(matchesDangerousPattern("require.resolve('mod')").matched)
})

patterns('detects dynamic import()', () => {
  assert.ok(matchesDangerousPattern("import('child_process')").matched)
})

patterns('detects global / globalThis', () => {
  assert.ok(matchesDangerousPattern('globalThis.process').matched)
  assert.ok(matchesDangerousPattern('global.process').matched)
})

patterns('detects __dirname / __filename', () => {
  assert.ok(matchesDangerousPattern('__dirname').matched)
  assert.ok(matchesDangerousPattern('__filename').matched)
})

patterns('detects prototype chain exploitation', () => {
  assert.ok(matchesDangerousPattern('[].constructor.constructor("code")()').matched)
  assert.ok(matchesDangerousPattern('obj.__proto__').matched)
  assert.ok(matchesDangerousPattern('Object.getPrototypeOf(x)').matched)
})

patterns('detects indirect eval via setTimeout/setInterval with string', () => {
  assert.ok(matchesDangerousPattern('setTimeout("alert(1)", 0)').matched)
  assert.ok(matchesDangerousPattern("setInterval('code', 100)").matched)
})

patterns('allows safe expressions', () => {
  assert.not.ok(matchesDangerousPattern('title').matched)
  assert.not.ok(matchesDangerousPattern('frontmatter.title').matched)
  assert.not.ok(matchesDangerousPattern('Math.random()').matched)
  assert.not.ok(matchesDangerousPattern('Date.now()').matched)
  assert.not.ok(matchesDangerousPattern('JSON.stringify(data)').matched)
  assert.not.ok(matchesDangerousPattern('items.map(x => x.name)').matched)
  assert.not.ok(matchesDangerousPattern('count + 1').matched)
  assert.not.ok(matchesDangerousPattern('`hello ${name}`').matched)
})

patterns.run()

// ===================================================================
// Unit tests – module specifier check
// ===================================================================

const modules = suite('isDangerousModule')

modules('flags Node.js built-ins', () => {
  assert.ok(isDangerousModule('child_process'))
  assert.ok(isDangerousModule('fs'))
  assert.ok(isDangerousModule('fs/promises'))
  assert.ok(isDangerousModule('net'))
  assert.ok(isDangerousModule('os'))
  assert.ok(isDangerousModule('vm'))
  assert.ok(isDangerousModule('http'))
  assert.ok(isDangerousModule('worker_threads'))
})

modules('flags node: prefixed imports', () => {
  assert.ok(isDangerousModule('node:fs'))
  assert.ok(isDangerousModule('node:child_process'))
  assert.ok(isDangerousModule('node:crypto'))
})

modules('allows safe modules', () => {
  assert.not.ok(isDangerousModule('react'))
  assert.not.ok(isDangerousModule('lodash'))
  assert.not.ok(isDangerousModule('left-pad'))
  assert.not.ok(isDangerousModule('./my-component'))
  assert.not.ok(isDangerousModule('../utils/helper'))
})

modules.run()

// ===================================================================
// Integration tests – blockDangerousJS (default: true)
// ===================================================================

const dangerous = suite('blockDangerousJS')

dangerous('blocks eval() in expressions', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '# Hello\n\n{eval("malicious code")}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
  assert.match(error.message, 'eval')
})

dangerous('blocks require() in expressions', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{require("child_process").execSync("whoami")}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('blocks new Function() in expressions', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{new Function("return process.env")()}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('blocks process.env access', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{process.env.SECRET_KEY}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('blocks dynamic import()', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{import("child_process")}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('blocks import from dangerous modules', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `import {execSync} from 'child_process'\n\n# Hello`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Import from dangerous module blocked')
  assert.match(error.message, 'child_process')
})

dangerous('blocks import from node: prefixed modules', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `import fs from 'node:fs'\n\n# Hello`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Import from dangerous module blocked')
})

dangerous('blocks __proto__ access', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{({}).__proto__}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('blocks constructor chain exploitation', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: '{[].constructor.constructor("return process")()}',
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

dangerous('allows safe MDX content', async () => {
  const {code} = await bundleMDX({
    source: `---
title: Safe Post
---

# Hello World

This is **safe** content with a variable: {frontmatter.title}
`,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))
  assert.match(container.innerHTML, 'Hello World')
  assert.match(container.innerHTML, 'safe')
})

dangerous('allows safe expressions like Math.random()', async () => {
  const {code} = await bundleMDX({
    source: `export const num = Math.round(3.7)\n\n# Number is {num}`,
  })

  const mdxExport = getMDXExport(code)
  assert.is(mdxExport.num, 4)
})

dangerous('can be disabled with blockDangerousJS: false', async () => {
  // This should NOT throw because we explicitly disabled the check
  const {code} = await bundleMDX({
    source: `export const env = "test"\n\n# Env: {env}`,
    blockDangerousJS: false,
  })

  assert.ok(code)
})

dangerous.run()

// ===================================================================
// Integration tests – blockJS
// ===================================================================

const blockAll = suite('blockJS')

blockAll('strips all JS expressions', async () => {
  const {code} = await bundleMDX({
    source: `# Title\n\nBefore {eval("danger")} After\n\n{process.env.SECRET}`,
    blockJS: true,
    blockDangerousJS: false,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  // Expressions should be stripped; surrounding text should remain
  assert.match(container.innerHTML, 'Title')
  assert.match(container.innerHTML, 'Before')
  assert.match(container.innerHTML, 'After')
  assert.not.match(container.innerHTML, 'danger')
  assert.not.match(container.innerHTML, 'SECRET')
})

blockAll('strips safe expressions too', async () => {
  const {code} = await bundleMDX({
    source: `# Title\n\n{1 + 1}`,
    blockJS: true,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'Title')
  assert.not.match(container.innerHTML, '2')
})

blockAll('preserves static MDX content', async () => {
  const {code} = await bundleMDX({
    source: `---
title: Static Content
---

# Hello World

This is a paragraph with **bold** and *italic* text.

- list item 1
- list item 2
`,
    blockJS: true,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'Hello World')
  assert.match(container.innerHTML, '<strong>bold</strong>')
  assert.match(container.innerHTML, '<em>italic</em>')
  assert.match(container.innerHTML, 'list item 1')
})

blockAll('blockJS takes precedence over blockDangerousJS', async () => {
  // When both are true, blockJS should win (strip all) rather than throw
  const {code} = await bundleMDX({
    source: `# Title\n\n{eval("code")}`,
    blockJS: true,
    blockDangerousJS: true,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'Title')
  assert.not.match(container.innerHTML, 'code')
})

blockAll.run()

// ===================================================================
// Integration tests – runtime dangerous globals shadow
// ===================================================================

const runtime = suite('runtime globals shadow')

runtime('DANGEROUS_GLOBALS_SHADOW contains expected keys', () => {
  const expected = [
    'eval',
    'Function',
    'process',
    'require',
    'global',
    'globalThis',
    '__dirname',
    '__filename',
  ]
  for (const key of expected) {
    assert.ok(
      key in DANGEROUS_GLOBALS_SHADOW,
      `Expected "${key}" in DANGEROUS_GLOBALS_SHADOW`,
    )
    assert.is(DANGEROUS_GLOBALS_SHADOW[key], undefined)
  }
})

runtime('getMDXExport shadows dangerous globals', async () => {
  // Use exported functions so typeof checks happen at call time (not at
  // esbuild compile time where the minifier may constant-fold them).
  // Disable minification to prevent esbuild from inlining typeof results.
  //
  // NOTE: `require` is NOT tested here because esbuild rewrites `require`
  // references to its internal `__require` shim, bypassing our parameter
  // shadow.  The primary defence for require() is the remark plugin which
  // blocks it before esbuild compilation.
  const {code} = await bundleMDX({
    source: `
export function checkEval() { return typeof eval }
export function checkFunction() { return typeof Function }
export function checkProcess() { return typeof process }
export function checkGlobal() { return typeof global }
export function checkGlobalThis() { return typeof globalThis }
export function checkDirname() { return typeof __dirname }
export function checkFilename() { return typeof __filename }

# Test
`.trim(),
    blockDangerousJS: false,
    esbuildOptions: options => {
      options.minify = false
      return options
    },
  })

  const mdxExport = getMDXExport(code)
  assert.is(mdxExport.checkEval(), 'undefined')
  assert.is(mdxExport.checkFunction(), 'undefined')
  assert.is(mdxExport.checkProcess(), 'undefined')
  assert.is(mdxExport.checkGlobal(), 'undefined')
  assert.is(mdxExport.checkGlobalThis(), 'undefined')
  assert.is(mdxExport.checkDirname(), 'undefined')
  assert.is(mdxExport.checkFilename(), 'undefined')
})

runtime('user-supplied globals can override shadows', async () => {
  const {code} = await bundleMDX({
    source: `export const testVal = typeof myProcess\n\n# Test`,
    globals: {'my-process': 'myProcess'},
    blockDangerousJS: false,
  })

  const mdxExport = getMDXExport(code, {myProcess: {env: {NODE_ENV: 'test'}}})
  assert.is(mdxExport.testVal, 'object')
})

runtime.run()

// ===================================================================
// Integration tests – complex attack vectors
// ===================================================================

const attacks = suite('attack vectors')

attacks('blocks RCE via MDX expression with require + execSync', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `# Innocent Title\n\n{require('child_process').execSync('cat /etc/passwd').toString()}`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

attacks('blocks globalThis escape', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `{globalThis.constructor.constructor("return this")().process.exit()}`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

attacks('blocks indirect eval via setTimeout with string arg', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `{setTimeout("alert(document.cookie)", 0)}`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Dangerous JavaScript expression blocked')
})

attacks('blocks import from fs module', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `import {readFileSync} from 'fs'\n\n{readFileSync('/etc/passwd', 'utf8')}`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Import from dangerous module blocked')
})

attacks('blocks import from vm module', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `import {runInNewContext} from 'vm'\n\n# Hello`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Import from dangerous module blocked')
})

attacks('blocks import from os module', async () => {
  const error = /** @type Error */ (
    await bundleMDX({
      source: `import os from 'os'\n\n{os.hostname()}`,
    }).catch(e => e)
  )
  assert.instance(error, Error)
  assert.match(error.message, 'Import from dangerous module blocked')
})

attacks.run()

// ===================================================================
// Backward compatibility
// ===================================================================

const compat = suite('backward compatibility')

compat('existing tests still pass with default options', async () => {
  const mdxSource = `
---
title: Example Post
---

# Title

export const name = 'World'

Hello {name}!
`.trim()

  const {code, frontmatter} = await bundleMDX({source: mdxSource})

  assert.equal(frontmatter.title, 'Example Post')

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'Title')
  assert.match(container.innerHTML, 'World')
})

compat('frontmatter expressions still work', async () => {
  const {code} = await bundleMDX({
    source: `---
title: My Post
---

# {frontmatter.title}
`,
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'My Post')
})

compat('component imports still work', async () => {
  const {code} = await bundleMDX({
    source: `import Demo from './demo'\n\n<Demo />`,
    files: {
      './demo.tsx': `export default () => <div>Demo works!</div>`,
    },
  })

  const Component = getMDXComponent(code)
  const {container} = render(React.createElement(Component))

  assert.match(container.innerHTML, 'Demo works!')
})

compat.run()
