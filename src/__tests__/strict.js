import './setup-tests.js'
import {mkdtemp, mkdir, writeFile, symlink, rm} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {suite} from 'uvu'
import * as assert from 'uvu/assert'
import React from 'react'
import {renderToStaticMarkup} from 'react-dom/server'
import * as preactRuntime from 'preact/jsx-runtime'
import {render as renderPreact} from '@testing-library/preact'
import * as vueRuntime from 'vue/jsx-runtime'
import {render as renderVue} from '@testing-library/vue'
import * as honoRuntime from 'hono/jsx/jsx-runtime'
import {VFile} from 'vfile'
import {bundleMDX} from '../index.js'
import {getMDXComponent, getMDXExport} from '../client/react.js'
import {getMDXComponent as getJSXComponent} from '../client/jsx.js'
import {STATIC_PREFIX, STATIC_LIMITS} from '../static-policy.js'

const test = suite('strict default security boundary')
/** @param {string} code */
const html = code =>
  renderToStaticMarkup(React.createElement(getMDXComponent(code)))
/** @param {string} source @param {string | RegExp} message */
async function rejected(source, message) {
  const error = await bundleMDX({source}).catch(e => e)
  assert.instance(error, Error)
  assert.match(error.message, message)
}

test('returns data and renders Markdown and frontmatter without evaluating code', async () => {
  const result = await bundleMDX({
    source:
      '---\ntitle: Safe\npublished: 2021-02-13\n---\n# {frontmatter.title}\n\nA **strong** word.',
  })
  assert.ok(result.code.startsWith(STATIC_PREFIX))
  assert.equal(result.errors, [])
  assert.equal(result.frontmatter.published, new Date('2021-02-13'))
  assert.is(getMDXExport(result.code).frontmatter.published, '2021-02-13')
  assert.match(html(result.code), '<h1>Safe</h1>')
  assert.match(html(result.code), '<strong>strong</strong>')
  assert.match(result.matter.stringify('yaml'), 'title: Safe')
  assert.match(result.matter.stringify('json'), '---json')
  assert.throws(() => result.matter.stringify('js'), /supports YAML and JSON/)
})

test('supports literal data, own frontmatter references, arrays, and static attributes', async () => {
  const {code} = await bundleMDX({
    source:
      '---\ntitle: Safe\nlabels: [one, two]\n---\n<div title={frontmatter["title"]}>{frontmatter.labels} {42} {false} {null}</div>',
  })
  assert.match(html(code), 'title="Safe"')
  assert.match(html(code), 'onetwo')
  assert.match(html(code), '42')
})

test('supports TOML and JSON frontmatter using data parsers only', async () => {
  for (const source of [
    '+++\ntitle = "Safe"\n+++\n# {frontmatter.title}',
    '---json\n{"title":"Safe"}\n---\n# {frontmatter.title}',
  ]) {
    const {code, frontmatter} = await bundleMDX({source})
    assert.is(frontmatter.title, 'Safe')
    assert.match(html(code), '<h1>Safe</h1>')
  }
})

test('handles VFiles and UTF-8 byte input', async () => {
  for (const source of [
    new VFile('# Safe'),
    new VFile(new TextEncoder().encode('# Safe')),
  ]) {
    const {code} = await bundleMDX({source})
    assert.match(html(code), '<h1>Safe</h1>')
  }
})

test('rejects the previously identified dynamic-code path before producing an artifact', async () => {
  await rejected(
    "{(() => {})['constructor']('return 42')()}",
    /only literal values/,
  )
})

test('rejects executable exports, calls, and functions without evaluating them', async () => {
  await rejected(
    'export const pending = (() => { for (;;) {} })()\n\n# Static',
    /Imports and exports require trusted/,
  )
  await rejected('{Math.random()}', /only literal values/)
  await rejected('{1 + 1}', /only literal values/)
})

test('rejects relative, absolute, builtin, and package imports without resolving them', async () => {
  for (const source of [
    "import data from '../private.json'",
    "import data from '/missing/private.json'",
    "import value from 'node:fs'",
    "import Component from 'mdx-test-data'",
  ]) {
    await rejected(source + '\n\n# Static', /strict mode does not resolve/)
  }
})

test('blockJS strips source modules and dynamic attributes but still validates static HTML', async () => {
  const {code} = await bundleMDX({
    source:
      'import data from "../missing.json"\n\nexport const value = 1\n\n<div title="static" style={value} {...data}>Before {value} after</div>',
    blockJS: true,
  })
  assert.match(html(code), '<div title="static">Before  after</div>')
  const error = await bundleMDX({
    source: '<script>text</script>',
    blockJS: true,
  }).catch(e => e)
  assert.instance(error, Error)
  assert.match(error.message, /Element "script" is not allowed/)
})

for (const tag of [
  'script',
  'iframe',
  'style',
  'object',
  'embed',
  'svg',
  'math',
  'form',
  'input',
  'base',
  'meta',
  'link',
]) {
  test(`rejects the ${tag} element`, () =>
    rejected(`<${tag} />`, /not allowed in strict mode/))
}

for (const attribute of [
  'onClick="text"',
  'onerror="text"',
  'style="color:red"',
  'dangerouslySetInnerHTML="text"',
  'srcDoc="text"',
  'is="custom-element"',
]) {
  test(`rejects unsafe attribute ${attribute.split('=')[0]}`, () =>
    rejected(`<div ${attribute}>Safe</div>`, /Attribute .* is not allowed/))
}

for (const url of [
  'javascript:42',
  'vbscript:42',
  'data:text/html,text',
  'java\tscript:42',
]) {
  test(`rejects an unsafe URL scheme ${url.split(':')[0]}`, () =>
    rejected(`<a href="${url}">Safe</a>`, /URL|Control characters/))
}

test('rejects prototype and inherited property references', async () => {
  for (const source of [
    '{frontmatter.constructor}',
    '{frontmatter["__proto__"]}',
    '{frontmatter.toString}',
  ]) {
    await rejected(source, /property/)
  }
})

test('rejects executable or unsafe frontmatter and unsupported data', async () => {
  await rejected(
    '---javascript\n({title: "not data"})\n---\n# Safe',
    /JavaScript frontmatter is disabled/,
  )
  await rejected(
    '---\n__proto__: {test: true}\n---\n# Safe',
    /Unsafe frontmatter property/,
  )
  await rejected(
    '---json\n{"constructor": {}}\n---\n# Safe',
    /Unsafe frontmatter property/,
  )
  await rejected('---\n- not a mapping\n---\n# Safe', /must be a mapping/)
})

test('enforces source, node, and depth ceilings', async () => {
  const cases = [
    {source: 'x'.repeat(STATIC_LIMITS.maxSourceBytes + 1)},
    {source: '# Safe', securityLimits: {maxNodes: 1}},
    {source: '---\na: {b: {c: 1}}\n---\n# Safe', securityLimits: {maxDepth: 1}},
    {
      source: '# Safe',
      securityLimits: {maxSourceBytes: STATIC_LIMITS.maxSourceBytes + 1},
    },
  ]
  for (const options of cases) {
    const error = await bundleMDX(options).catch(e => e)
    assert.instance(error, Error)
    assert.match(error.message, /limit|between/)
  }
})

test('terminates a parser worker at its deadline using benign input', async () => {
  const error = await bundleMDX({
    source: '# Safe',
    securityLimits: {timeoutMs: 1},
  }).catch(e => e)
  assert.instance(error, Error)
  assert.match(error.message, /timed out/)
  const {code} = await bundleMDX({source: '# Worker recovered'})
  assert.match(html(code), 'Worker recovered')
})

test('bounds concurrent parser requests and recovers after queue saturation', async () => {
  const results = await Promise.allSettled(
    Array.from({length: 11}, () =>
      bundleMDX({source: '# Safe', securityLimits: {timeoutMs: 1}}),
    ),
  )
  assert.ok(results.every(result => result.status === 'rejected'))
  assert.ok(
    results.some(
      result =>
        result.status === 'rejected' && /busy/.test(result.reason.message),
    ),
  )
  const {code} = await bundleMDX({source: '# Queue recovered'})
  assert.match(html(code), 'Queue recovered')
})

test('counts UTF-8 bytes and rejects invalid resource configuration', async () => {
  const cases = [
    {source: '한'.repeat(100), securityLimits: {maxSourceBytes: 100}},
    {source: '# Safe', securityLimits: {timeoutMs: Number.NaN}},
    {source: '# Safe', securityLimits: {maxDepth: 0}},
    {source: '# Safe', trusted: true, securityLimits: {timeoutMs: 1}},
  ]
  for (const options of cases) {
    const error = await bundleMDX(options).catch(e => e)
    assert.instance(error, Error)
    assert.match(error.message, /limit|between|strict mode/)
  }
})

test('rejects custom executable configuration unless the developer opts into trusted mode', async () => {
  const options = [
    {files: {}},
    {globals: {}},
    {mdxOptions: () => ({})},
    {esbuildOptions: () => ({})},
    {grayMatterOptions: () => ({})},
    {blockDangerousJS: false},
  ]
  for (const configuration of options) {
    let invoked = false
    const error = await bundleMDX({
      source: '# Safe',
      ...configuration,
      ...('mdxOptions' in configuration
        ? {
            mdxOptions: () => {
              invoked = true
              return {}
            },
          }
        : {}),
    }).catch(e => e)
    assert.instance(error, Error)
    assert.match(error.message, /trusted: true/)
    assert.not.ok(invoked)
  }
})

test('uses real paths for explicit file input and refuses outside files and symlinks', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mdx-strict-files-'))
  try {
    const root = path.join(directory, 'content')
    await mkdir(root)
    await writeFile(path.join(root, 'safe.mdx'), '# Safe')
    await writeFile(path.join(directory, 'outside.mdx'), '# Outside')
    await symlink(
      path.join(directory, 'outside.mdx'),
      path.join(root, 'link.mdx'),
    )
    const {code} = await bundleMDX({file: 'safe.mdx', cwd: root})
    assert.match(html(code), '<h1>Safe</h1>')
    for (const file of ['../outside.mdx', 'link.mdx']) {
      const error = await bundleMDX({file, cwd: root}).catch(e => e)
      assert.instance(error, Error)
      assert.match(error.message, /outside the allowed cwd/)
    }
  } finally {
    await rm(directory, {recursive: true, force: true})
  }
})

test('rejects raw executable client code unless separately marked trusted', () => {
  assert.throws(() => getMDXExport('return {}'), /explicit .*trusted: true/)
  assert.throws(
    () => getJSXComponent('return {}', {_jsx_runtime: preactRuntime}),
    /explicit .*trusted: true/,
  )
})

test('renders strict data when dynamic function construction is unavailable', async () => {
  const {code} = await bundleMDX({source: '# Data only'})
  const original = Object.getOwnPropertyDescriptor(globalThis, 'Function')
  if (!original) throw new Error('Function descriptor is unavailable')
  try {
    Object.defineProperty(globalThis, 'Function', {
      value: () => {
        throw new Error('Dynamic evaluation is disabled')
      },
    })
    assert.match(html(code), '<h1>Data only</h1>')
    assert.throws(() => getMDXExport('return {}'), /trusted: true/)
  } finally {
    Object.defineProperty(globalThis, 'Function', original)
  }
})

test('does not inherit the trusted capability from a prototype', async () => {
  const options = Object.assign(Object.create({trusted: true}), {
    source: '# Data only',
  })
  const {code} = await bundleMDX(options)
  assert.ok(code.startsWith(STATIC_PREFIX))
  assert.throws(
    () => getMDXExport('return {}', undefined, Object.create({trusted: true})),
    /trusted: true/,
  )
})

test('validates forged static artifacts at the client boundary', () => {
  for (const node of [
    {tag: 'script', props: {}, children: []},
    {tag: 'div', props: {onClick: 'text'}, children: []},
    {tag: 'a', props: {href: 'javascript:42'}, children: []},
    {
      tag: 'img',
      props: {src: 'https://example.com/image.png'},
      children: ['text'],
    },
  ]) {
    const code =
      STATIC_PREFIX +
      JSON.stringify({version: 1, frontmatter: {}, tree: [node]})
    assert.throws(() => getMDXExport(code), /not allowed|Void elements/)
  }
  assert.throws(
    () => getMDXExport(STATIC_PREFIX + '{'),
    /Invalid static artifact/,
  )
})

test('enforces artifact bytes, nodes, depth, and frontmatter keys before rendering', () => {
  /** @param {any[]} tree @param {any} [frontmatter] */
  const packet = (tree, frontmatter = {}) =>
    STATIC_PREFIX + JSON.stringify({version: 1, frontmatter, tree})
  assert.throws(
    () => getMDXExport(STATIC_PREFIX + ' '.repeat(STATIC_LIMITS.maxCodeBytes)),
    /byte limit/,
  )
  assert.throws(
    () => getMDXExport(packet(Array(STATIC_LIMITS.maxNodes + 1).fill('text'))),
    /node or depth limit/,
  )
  /** @type {any} */
  let nested = 'text'
  for (let depth = 0; depth < STATIC_LIMITS.maxDepth + 2; depth++)
    nested = {tag: 'div', props: {}, children: [nested]}
  assert.throws(() => getMDXExport(packet([nested])), /node or depth limit/)
  assert.throws(
    () => getMDXExport(packet([], JSON.parse('{"__proto__":{}}'))),
    /Unsafe frontmatter property/,
  )
})

test('allows safe host components but rejects unsafe native element replacements', async () => {
  const {code} = await bundleMDX({source: '# Safe'})
  const Content = getMDXComponent(code)
  const output = renderToStaticMarkup(
    React.createElement(Content, {
      components: {
        h1: ({children}) => React.createElement('strong', null, children),
        wrapper: 'section',
      },
    }),
  )
  assert.equal(output, '<section><strong>Safe</strong></section>')
  assert.throws(
    () =>
      renderToStaticMarkup(
        React.createElement(Content, {components: {h1: 'script'}}),
      ),
    /not allowed/,
  )
  assert.throws(
    () => getMDXExport(code, {unused: 'value'}),
    /does not accept executable globals/,
  )
})

test('preserves standard Markdown content and reference links', async () => {
  const {code} = await bundleMDX({
    source:
      '# Heading\n\n> Quote\n\n- one\n- two\n\n2. second\n\n[Docs][docs]\n\n![Image][picture]\n\n[docs]: https://example.com "Docs"\n[picture]: https://example.com/image.png\n\n`inline`\n\n---\n\nLine  \nbreak\n\n{["literal", 2, null]}',
  })
  const output = html(code)
  for (const value of [
    '<blockquote>',
    '<ul>',
    '<ol start="2">',
    'href="https://example.com"',
    'alt="Image"',
    '<code>inline</code>',
    '<hr',
    '<br',
    'literal2',
  ])
    assert.match(output, value)
})

test('escapes code text, namespaces IDs, and isolates external link targets', async () => {
  const {code} = await bundleMDX({
    source:
      '<a id="section" href="#section" target="_blank">Safe</a>\n\n```html\n<script>text</script>\n```',
  })
  const output = html(code)
  assert.match(output, 'id="mdx-content-section"')
  assert.match(output, 'href="#mdx-content-section"')
  assert.match(output, 'noopener noreferrer')
  assert.match(output, '&lt;script&gt;')
  assert.not.match(code, '</script>')
})

test('renders safe artifacts in Preact, Vue, and Hono runtimes', async () => {
  const {code} = await bundleMDX({source: '# Safe\n\nA **strong** word.'})
  const preact = getJSXComponent(code, {_jsx_runtime: preactRuntime})
  const preactView = renderPreact(preact({}))
  assert.match(preactView.container.innerHTML, '<h1>Safe</h1>')
  preactView.unmount()
  const vue = getJSXComponent(code, {_jsx_runtime: vueRuntime})
  const vueView = renderVue(vue)
  assert.match(vueView.container.innerHTML, '<strong>strong</strong>')
  vueView.unmount()
  const hono = getJSXComponent(code, {_jsx_runtime: honoRuntime})
  assert.match(hono({}).toString(), '<h1>Safe</h1>')
})

test('preserves explicitly trusted bundling with a second client opt-in', async () => {
  const {code} = await bundleMDX({
    source: 'export const count = 2\n\n# {count}',
    trusted: true,
  })
  assert.throws(() => getMDXExport(code), /trusted: true/)
  const exported = getMDXExport(code, undefined, {trusted: true})
  assert.is(exported.count, 2)
  assert.match(
    renderToStaticMarkup(React.createElement(exported.default)),
    '<h1>2</h1>',
  )
})

test.run()
