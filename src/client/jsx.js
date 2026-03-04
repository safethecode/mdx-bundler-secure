import {DANGEROUS_GLOBALS_SHADOW} from '../security.js'

/**
 * @typedef {import('../types').MDXContentProps} MDXContentProps
 */

/**
 *
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} jsxGlobals - JSX globals
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 * @return {(props: MDXContentProps) => JSX.Element}
 */
function getMDXComponent(code, jsxGlobals, globals) {
  const mdxExport = getMDXExport(code, jsxGlobals, globals)
  return mdxExport.default
}

/**
 * @template {{}} ExportedObject
 * @template {{}} Frontmatter
 * @type {import('../types').MDXJsxExportFunction<ExportedObject, Frontmatter>}
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} jsxGlobals - JSX globals
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 *
 */
function getMDXExport(code, jsxGlobals, globals) {
  // Shadow dangerous globals so that common attack primitives (eval, process,
  // require, etc.) are `undefined` inside the evaluated scope.  User-supplied
  // globals can still override these if explicitly provided.
  const scope = {...DANGEROUS_GLOBALS_SHADOW, ...jsxGlobals, ...globals}
  // eslint-disable-next-line
  const fn = new Function(...Object.keys(scope), code)
  return fn(...Object.values(scope))
}

export {getMDXComponent, getMDXExport}
