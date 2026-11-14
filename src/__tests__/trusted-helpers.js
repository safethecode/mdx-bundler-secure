// Compatibility tests opt in at both boundaries. Strict-mode tests import the
// public functions directly and never execute rejected JavaScript inputs.
import {bundleMDX as bundle} from '../index.js'
import {
  getMDXComponent as component,
  getMDXExport as exported,
} from '../client/react.js'
import {
  getMDXComponent as jsxComponent,
  getMDXExport as jsxExport,
} from '../client/jsx.js'

/** @type {typeof bundle} */
const bundleTrustedMDX = options => bundle({...options, trusted: true})
/** @type {typeof component} */
const getTrustedMDXComponent = (code, globals) =>
  component(code, globals, {trusted: true})
/** @type {typeof exported} */
const getTrustedMDXExport = (code, globals) =>
  exported(code, globals, {trusted: true})
/** @type {typeof jsxComponent} */
const getTrustedJSXComponent = (code, jsxGlobals, globals) =>
  jsxComponent(code, jsxGlobals, globals, {trusted: true})
/** @type {typeof jsxExport} */
const getTrustedJSXExport = (code, jsxGlobals, globals) =>
  jsxExport(code, jsxGlobals, globals, {trusted: true})

export {
  bundleTrustedMDX,
  getTrustedMDXComponent,
  getTrustedMDXExport,
  getTrustedJSXComponent,
  getTrustedJSXExport,
}
