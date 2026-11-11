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
    /Dangerous JavaScript expression blocked/,
  )
  console.log('CommonJS, ESM, client entries, and security smoke tests passed')
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
