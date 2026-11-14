const assert = require('node:assert/strict')
const React = require('react')
const {renderToStaticMarkup} = require('react-dom/server')
const {bundleMDX} = require('../dist/index.js')
const {getMDXComponent, getMDXExport} = require('../client')

async function main() {
  const {code, frontmatter} = await bundleMDX({
    source: '---\ntitle: Packaged build\n---\n\n# {frontmatter.title}',
  })
  assert.equal(frontmatter.title, 'Packaged build')
  assert.equal(getMDXExport(code).frontmatter.title, 'Packaged build')
  assert.equal(
    renderToStaticMarkup(React.createElement(getMDXComponent(code))),
    '<h1>Packaged build</h1>',
  )
  assert.equal(typeof require('../client/react').getMDXComponent, 'function')
  assert.equal(typeof require('../client/jsx').getMDXComponent, 'function')
  const esm = await import('../dist/index.js')
  assert.equal(typeof esm.bundleMDX, 'function')
  await assert.rejects(
    bundleMDX({source: '{eval("blocked")}'}),
    /only literal values/,
  )
  await assert.rejects(
    bundleMDX({source: '<script>text</script>', blockJS: true}),
    /not allowed in strict mode/,
  )
  await assert.rejects(
    bundleMDX({source: "import data from '../private.json'\n\n# Static"}),
    /strict mode does not resolve/,
  )
  assert.throws(() => getMDXExport('return {}'), /trusted: true/)
  const {code: trustedCode} = await bundleMDX({
    source: 'export const count = 2\n\n# {count}',
    trusted: true,
  })
  assert.throws(() => getMDXExport(trustedCode), /trusted: true/)
  assert.equal(getMDXExport(trustedCode, undefined, {trusted: true}).count, 2)
  console.log(
    'Strict data, trusted opt-in, CommonJS, ESM, client entries, and security checks passed',
  )
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
