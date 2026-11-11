import {bundleMDX} from '../dist/index.js'
import {getMDXComponent, getMDXExport} from '../client/index.js'
import {getMDXExport as getJSXExport} from '../client/jsx.js'

async function checkConsumerTypes() {
  const result = await bundleMDX<{title: string}>({
    source: '---\ntitle: Typed frontmatter\n---\n# Test',
    blockJS: true,
  })
  const title: string = result.frontmatter.title
  // @ts-expect-error The caller's frontmatter shape must be preserved.
  const missing: number = result.frontmatter.missing
  const exported = getMDXExport<{count: number}, {title: string}>(result.code)
  const count: number = exported.count
  const exportedTitle: string = exported.frontmatter.title
  const jsxExported = getJSXExport<{count: number}, {title: string}>(
    result.code,
    {},
  )
  const jsxCount: number = jsxExported.count
  return {
    title,
    count,
    exportedTitle,
    jsxCount,
    missing,
    Component: getMDXComponent(result.code),
  }
}

void checkConsumerTypes
