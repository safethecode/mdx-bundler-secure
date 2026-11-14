import * as React from 'react'
import * as ReactDOM from 'react-dom'
import * as _jsx_runtime from 'react/jsx-runtime'
import {DANGEROUS_GLOBALS_SHADOW} from '../security.js'
import {STATIC_PREFIX, createStaticExport, fail} from '../static-policy.js'

/**
 * @typedef {import('../types').MDXContentProps} MDXContentProps
 */

/**
 *
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 * @param {import('../types').ClientOptions} [options]
 * @return {(props: MDXContentProps) => JSX.Element}
 */
function getMDXComponent(code, globals, options) {
  const mdxExport = getMDXExport(code, globals, options)
  return mdxExport.default
}

/**
 * @template {{}} [ExportedObject=Record<string, any>]
 * @template {Record<string, unknown>} [Frontmatter=Record<string, unknown>]
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 * @param {import('../types').ClientOptions} [options]
 * @returns {import('../types').MDXExport<ExportedObject, Frontmatter>}
 *
 */
function getMDXExport(code, globals, options = {}) {
  if (typeof code !== 'string') return fail('code must be a string')
  if (
    !Object.hasOwn(options, 'trusted') ||
    options.trusted !== true ||
    code.startsWith(STATIC_PREFIX)
  ) {
    if (globals && Object.keys(globals).length)
      return fail('Static content does not accept executable globals')
    return /** @type {import('../types').MDXExport<ExportedObject, Frontmatter>} */ (
      createStaticExport(code, {
        jsx: _jsx_runtime.jsx,
        Fragment: React.Fragment,
      })
    )
  }
  const jsxGlobals = {React, ReactDOM, _jsx_runtime}
  // Shadow dangerous globals so that common attack primitives (eval, process,
  // require, etc.) are `undefined` inside the evaluated scope.  User-supplied
  // globals can still override these if explicitly provided.
  const scope = {...DANGEROUS_GLOBALS_SHADOW, ...jsxGlobals, ...globals}
  // eslint-disable-next-line no-new-func
  const fn = new Function(...Object.keys(scope), code)
  return fn(...Object.values(scope))
}

export {getMDXComponent, getMDXExport}
