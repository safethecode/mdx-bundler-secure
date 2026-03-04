/**
 * Security utilities for mdx-bundler.
 *
 * Provides remark plugins and runtime helpers to mitigate arbitrary code
 * execution when processing untrusted MDX content (related to CVE-2026-0969).
 */

/**
 * Dangerous JavaScript patterns checked inside MDX expression nodes.
 * Each entry is a regex that, when matched against the raw expression text,
 * indicates a potential code-injection vector.
 *
 * @type {RegExp[]}
 */
const DANGEROUS_JS_PATTERNS = [
  // Direct dangerous function calls
  /\beval\s*\(/,
  /\bFunction\s*\(/,
  /\bnew\s+Function\b/,

  // Node.js process access
  /\bprocess\.\w/,
  /\bprocess\s*\[/,

  // Module loading
  /\brequire\s*\(/,
  /\brequire\s*\.\s*resolve/,
  /\bimport\s*\(/,

  // Global scope access
  /\bglobalThis\b/,
  /\bglobal\b/,

  // File system info leakage
  /\b__dirname\b/,
  /\b__filename\b/,

  // Prototype chain exploitation
  /\.constructor\s*[\[.(]/,
  /\.__proto__\b/,
  /Object\s*\.\s*getPrototypeOf/,

  // Indirect eval via string-accepting timer APIs
  /\bsetTimeout\s*\(\s*['"`:]/,
  /\bsetInterval\s*\(\s*['"`:]/,
]

/**
 * Node.js built-in modules that provide system-level access.
 *
 * @type {Set<string>}
 */
const DANGEROUS_MODULES = new Set([
  'child_process',
  'cluster',
  'dgram',
  'dns',
  'fs',
  'fs/promises',
  'http',
  'http2',
  'https',
  'inspector',
  'net',
  'os',
  'process',
  'tls',
  'v8',
  'vm',
  'worker_threads',
])

/**
 * Globals to shadow at `new Function()` evaluation time so that common
 * attack primitives are `undefined` inside the MDX component scope.
 *
 * Users who genuinely need any of these can pass them explicitly via the
 * `globals` parameter of `getMDXComponent` / `getMDXExport`.
 *
 * @type {Record<string, undefined>}
 */
const DANGEROUS_GLOBALS_SHADOW = {
  eval: undefined,
  Function: undefined,
  process: undefined,
  require: undefined,
  global: undefined,
  globalThis: undefined,
  __dirname: undefined,
  __filename: undefined,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Recursively visit every node in a unist/mdast tree and invoke `callback`
 * for each node.  Children are visited in reverse order so that splicing
 * during iteration is safe.
 *
 * @param {any} node
 * @param {(node: any, index: number|null, parent: any|null) => void} callback
 */
function walkTree(node, callback) {
  if (node.children) {
    for (let i = node.children.length - 1; i >= 0; i--) {
      walkTree(node.children[i], callback)
      callback(node.children[i], i, node)
    }
  }
}

/**
 * Check a JavaScript expression string against DANGEROUS_JS_PATTERNS.
 *
 * @param {string} value  The raw expression text.
 * @returns {{ matched: boolean, pattern?: RegExp }}
 */
function matchesDangerousPattern(value) {
  for (const pattern of DANGEROUS_JS_PATTERNS) {
    if (pattern.test(value)) {
      return {matched: true, pattern}
    }
  }
  return {matched: false}
}

/**
 * Check whether an import source refers to a dangerous Node.js built-in.
 *
 * @param {string} source  The module specifier (e.g. "child_process", "node:fs").
 * @returns {boolean}
 */
function isDangerousModule(source) {
  if (source.startsWith('node:')) {
    return true
  }
  return DANGEROUS_MODULES.has(source)
}

/**
 * Extract module specifiers from an ESM statement string.
 * Handles both `import ... from 'mod'` and `import 'mod'`.
 *
 * @param {string} value
 * @returns {string[]}
 */
function extractModuleSpecifiers(value) {
  /** @type {string[]} */
  const specifiers = []

  // import ... from 'module'  /  export ... from 'module'
  const fromMatches = value.matchAll(/(?:from|import)\s+['"]([^'"]+)['"]/g)
  for (const m of fromMatches) {
    specifiers.push(m[1])
  }

  return specifiers
}

// ---------------------------------------------------------------------------
// Remark plugin: remarkBlockJS
// ---------------------------------------------------------------------------

/**
 * Remark plugin that **strips all JavaScript expressions** from the MDX AST.
 *
 * When enabled, every `{expression}` in the MDX source is removed before
 * compilation, effectively disabling dynamic JavaScript in the content.
 *
 * @returns {(tree: any) => void}
 */
function remarkBlockJS() {
  return function transformer(tree) {
    walkTree(tree, (node, index, parent) => {
      if (
        parent &&
        index !== null &&
        (node.type === 'mdxFlowExpression' || node.type === 'mdxTextExpression')
      ) {
        parent.children.splice(index, 1)
      }
    })

    // Also strip JSX attribute value expressions (e.g. <div onClick={...} />)
    walkTree(tree, (node) => {
      if (
        (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') &&
        node.attributes
      ) {
        node.attributes = node.attributes.filter((/** @type {any} */ attr) => {
          // Remove spread expression attributes entirely
          if (attr.type === 'mdxJsxExpressionAttribute') return false

          // Remove attribute values that are expressions
          if (
            attr.value &&
            typeof attr.value === 'object' &&
            attr.value.type === 'mdxJsxAttributeValueExpression'
          ) {
            attr.value = null
          }
          return true
        })
      }
    })
  }
}

// ---------------------------------------------------------------------------
// Remark plugin: remarkBlockDangerousJS
// ---------------------------------------------------------------------------

/**
 * Remark plugin that **blocks known-dangerous JavaScript patterns** in MDX
 * expressions while still allowing safe expressions to pass through.
 *
 * This is a best-effort defence-in-depth layer.  It is NOT a sandbox and
 * cannot catch every possible attack.  For maximum safety, prefer
 * `blockJS: true` when processing untrusted content.
 *
 * @returns {(tree: any) => void}
 */
function remarkBlockDangerousJS() {
  return function transformer(tree) {
    // Check expression nodes
    walkTree(tree, (node) => {
      const value = expressionValue(node)
      if (value === null) return

      const result = matchesDangerousPattern(value)
      if (result.matched) {
        const preview = value.length > 100 ? value.substring(0, 100) + '…' : value
        throw new Error(
          `[mdx-bundler] Dangerous JavaScript expression blocked: "${preview}". ` +
            `If this content is trusted, set blockDangerousJS: false.`,
        )
      }
    })

    // Check JSX attribute expressions
    walkTree(tree, (node) => {
      if (
        (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') &&
        node.attributes
      ) {
        for (const attr of node.attributes) {
          let value = null

          if (attr.type === 'mdxJsxExpressionAttribute' && attr.value) {
            value = attr.value
          } else if (
            attr.value &&
            typeof attr.value === 'object' &&
            attr.value.type === 'mdxJsxAttributeValueExpression' &&
            attr.value.value
          ) {
            value = attr.value.value
          }

          if (value !== null) {
            const result = matchesDangerousPattern(value)
            if (result.matched) {
              const preview = value.length > 100 ? value.substring(0, 100) + '…' : value
              throw new Error(
                `[mdx-bundler] Dangerous JavaScript in JSX attribute blocked: "${preview}". ` +
                  `If this content is trusted, set blockDangerousJS: false.`,
              )
            }
          }
        }
      }
    })

    // Check ESM import / export statements for dangerous modules
    walkTree(tree, (node) => {
      if (node.type === 'mdxjsEsm' && node.value) {
        const specifiers = extractModuleSpecifiers(node.value)
        for (const specifier of specifiers) {
          if (isDangerousModule(specifier)) {
            throw new Error(
              `[mdx-bundler] Import from dangerous module blocked: "${specifier}". ` +
                `If this content is trusted, set blockDangerousJS: false.`,
            )
          }
        }
      }
    })
  }
}

/**
 * Return the JavaScript expression text for a node, or `null` if not an
 * expression node.
 *
 * @param {any} node
 * @returns {string|null}
 */
function expressionValue(node) {
  if (
    (node.type === 'mdxFlowExpression' || node.type === 'mdxTextExpression') &&
    typeof node.value === 'string'
  ) {
    return node.value
  }
  return null
}

export {
  remarkBlockJS,
  remarkBlockDangerousJS,
  DANGEROUS_JS_PATTERNS,
  DANGEROUS_MODULES,
  DANGEROUS_GLOBALS_SHADOW,
  matchesDangerousPattern,
  isDangerousModule,
}
