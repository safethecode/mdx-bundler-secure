import {bundleMDX} from '../dist/index.js'
import {getMDXComponent, getMDXExport} from '../client/index.js'
import {getMDXExport as getJSXExport} from '../client/jsx.js'

async function checkConsumerTypes() {
  const result = await bundleMDX<{title: string}>({
    source: '---\ntitle: Typed frontmatter\n---\n# Test',
    blockJS: true,
    securityLimits: {timeoutMs: 4000, maxSourceBytes: 100000},
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
  getMDXExport(result.code, undefined, {trusted: true})
  getMDXComponent(result.code, undefined, {trusted: true})
  getJSXExport(result.code, {}, undefined, {trusted: true})
  await bundleMDX({source: 'export const count = 2', trusted: true})
  // @ts-expect-error Opt-in is an explicit boolean controlled by the caller.
  await bundleMDX({source: '# Safe', trusted: 'true'})
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
