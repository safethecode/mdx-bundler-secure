import * as React from 'react'
import * as ReactDOM from 'react-dom'
import * as _jsx_runtime from 'react/jsx-runtime'
import {DANGEROUS_GLOBALS_SHADOW} from '../security.js'

/**
 * @typedef {import('../types').MDXContentProps} MDXContentProps
 */

/**
 *
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 * @return {(props: MDXContentProps) => JSX.Element}
 */
function getMDXComponent(code, globals) {
  const mdxExport = getMDXExport(code, globals)
  return mdxExport.default
}

/**
 * @template {{}} ExportedObject
 * @template {{}} Frontmatter
 * @type {import('../types').MDXExportFunction<ExportedObject, Frontmatter>}
 * @param {string} code - The string of code you got from bundleMDX
 * @param {Record<string, unknown>} [globals] - Any variables your MDX needs to have accessible when it runs
 *
 */
function getMDXExport(code, globals) {
  const jsxGlobals = {React, ReactDOM, _jsx_runtime}
  // Shadow dangerous globals so that common attack primitives (eval, process,
  // require, etc.) are `undefined` inside the evaluated scope.  User-supplied
  // globals can still override these if explicitly provided.
  const scope = {...DANGEROUS_GLOBALS_SHADOW, ...jsxGlobals, ...globals}
  // eslint-disable-next-line
  const fn = new Function(...Object.keys(scope), code)
  return fn(...Object.values(scope))
}

export {getMDXComponent, getMDXExport}
