import './setup-tests.js'
import {mkdtemp, rm, writeFile} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {suite} from 'uvu'
import * as assert from 'uvu/assert'
import {VFile} from 'vfile'
import remarkFrontmatter from 'remark-frontmatter'
import {bundleMDX} from '../index.js'
import {getMDXExport} from '../client/react.js'

const test = suite('frontmatter security')

for (const language of ['js', 'javascript', 'JS', 'JavaScript']) {
  test(`rejects executable ${language} frontmatter before evaluation`, async () => {
    const source = `---${language}\n(() => { throw new Error('frontmatter executed') })()\n---\n# Safe`
    const error = await bundleMDX({source, blockJS: true}).catch(e => e)
    assert.instance(error, Error)
    assert.match(error.message, 'JavaScript frontmatter is disabled')
  })
}

test('rejects JavaScript frontmatter in VFiles with expression checks disabled', async () => {
  const source = new VFile('---js\n({title: "executable"})\n---\n# Safe')
  const error = await bundleMDX({source, blockDangerousJS: false}).catch(e => e)
  assert.instance(error, Error)
  assert.match(error.message, 'JavaScript frontmatter is disabled')
})

test('rejects JavaScript frontmatter read from disk', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mdx-frontmatter-'))
  try {
    const file = path.join(directory, 'unsafe.mdx')
    await writeFile(file, '---javascript\n({title: "executable"})\n---\n# Safe')
    const error = await bundleMDX({file}).catch(e => e)
    assert.instance(error, Error)
    assert.match(error.message, 'JavaScript frontmatter is disabled')
  } finally {
    await rm(directory, {recursive: true, force: true})
  }
})

test('keeps YAML dates and aliases compatible in returned and exported data', async () => {
  const {code, frontmatter} = await bundleMDX({
    source: `---
published: 2021-02-13
author: &author
  name: Aaron
editor: *author
---
# Safe`,
  })
  assert.equal(frontmatter.published, new Date('2021-02-13'))
  assert.equal(frontmatter.editor, {name: 'Aaron'})
  const exported = getMDXExport(code).frontmatter
  assert.is(exported.published, '2021-02-13')
  assert.is(exported.author, exported.editor)
})

/** @param {string} source */
function bundleToml(source) {
  return bundleMDX({
    source,
    grayMatterOptions: options => ({
      ...options,
      delimiters: '+++',
      language: 'toml',
    }),
    mdxOptions: options => ({
      ...options,
      remarkPlugins: [
        [remarkFrontmatter, ['yaml', 'toml']],
        ...(options.remarkPlugins ?? []).slice(1),
      ],
    }),
  })
}

test('parses TOML using the patched parser in both frontmatter paths', async () => {
  const {code, frontmatter} = await bundleToml(`+++
title = "TOML"
items = [1, 2]
[details]
enabled = true
+++
# {frontmatter.title}`)
  const expected = {title: 'TOML', items: [1, 2], details: {enabled: true}}
  // smol-toml uses null-prototype tables; compare the serialized data shape.
  assert.equal(JSON.parse(JSON.stringify(frontmatter)), expected)
  assert.equal(
    JSON.parse(JSON.stringify(getMDXExport(code).frontmatter)),
    expected,
  )
})

test('rejects excessively nested TOML instead of exhausting the stack', async () => {
  const value = '['.repeat(2000) + '0' + ']'.repeat(2000)
  const error = await bundleToml(`+++\nvalue = ${value}\n+++\n# Safe`).catch(
    e => e,
  )
  assert.instance(error, Error)
  assert.not.instance(error, RangeError)
  assert.match(error.message, /nest|depth/i)
})

test('TOML prototype-like keys do not pollute Object.prototype', async () => {
  const {code} = await bundleToml(
    '+++\n__proto__.mdx_polluted = true\n+++\n# Safe',
  )
  getMDXExport(code)
  assert.not.ok(Object.hasOwn(Object.prototype, 'mdx_polluted'))
})

test.run()
