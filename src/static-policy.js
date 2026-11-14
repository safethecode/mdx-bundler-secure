// This module is shared with browser clients. It must not evaluate JavaScript
// or import server modules: the static artifact is data, not a program.
const STATIC_PREFIX = 'mdx-bundler-secure:static:v1\n'
const STATIC_LIMITS = Object.freeze({
  maxSourceBytes: 256 * 1024,
  maxCodeBytes: 2 * 1024 * 1024,
  maxNodes: 10000,
  maxDepth: 64,
  timeoutMs: 5000,
})
const forbiddenKeys = new Set(['__proto__', 'prototype', 'constructor'])
const tags = new Set(
  'a abbr b blockquote br caption code col colgroup dd del details div dl dt em figcaption figure h1 h2 h3 h4 h5 h6 hr i img kbd li mark ol p pre q s samp section small span strong sub summary sup table tbody td th thead tr u ul'.split(
    ' ',
  ),
)
const voidTags = new Set(['br', 'hr', 'img', 'col'])
const globalAttributes = new Set(
  'id className title lang dir role hidden tabIndex'.split(' '),
)
/** @type {Record<string, Set<string>>} */
const tagAttributes = {
  a: new Set(['href', 'target', 'rel']),
  img: new Set(['src', 'alt', 'width', 'height', 'loading', 'decoding']),
  ol: new Set(['start', 'reversed']),
  li: new Set(['value']),
  details: new Set(['open']),
  td: new Set(['colSpan', 'rowSpan']),
  th: new Set(['colSpan', 'rowSpan', 'scope']),
  col: new Set(['span']),
  colgroup: new Set(['span']),
}

/** @param {string} message @returns {never} */
function fail(message) {
  throw new Error(`[mdx-bundler-secure] ${message}`)
}

/** @param {string} value @param {number} maximum */
function checkBytes(value, maximum) {
  if (
    value.length > maximum ||
    new TextEncoder().encode(value).length > maximum
  ) {
    fail('Static content exceeds the byte limit')
  }
}

/** @param {{maxNodes?: number, maxDepth?: number}} [limits] */
function createBudget(limits = {}) {
  return {
    nodes: 0,
    bytes: 0,
    maxNodes: limits.maxNodes ?? STATIC_LIMITS.maxNodes,
    maxDepth: limits.maxDepth ?? STATIC_LIMITS.maxDepth,
  }
}

/** @param {ReturnType<typeof createBudget>} budget @param {number} depth */
function consume(budget, depth) {
  if (++budget.nodes > budget.maxNodes || depth > budget.maxDepth) {
    fail('Static content exceeds the node or depth limit')
  }
}

/**
 * Clone only bounded data. Repeated aliases count on every occurrence, so a
 * compact YAML alias graph cannot expand into an unbounded JSON artifact.
 * @param {any} value
 * @param {ReturnType<typeof createBudget>} budget
 * @param {number} [depth]
 * @param {boolean} [preserveDates]
 * @returns {any}
 */
function cloneData(value, budget, depth = 0, preserveDates = false) {
  consume(budget, depth)
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    budget.bytes += new TextEncoder().encode(value).length
    if (budget.bytes > STATIC_LIMITS.maxCodeBytes)
      fail('Frontmatter exceeds the byte limit')
    return value
  }
  if (value instanceof Date) {
    const iso = Date.prototype.toISOString.call(value)
    return preserveDates ? new Date(iso) : iso
  }
  if (Array.isArray(value)) {
    return value.map(item => cloneData(item, budget, depth + 1, preserveDates))
  }
  if (typeof value !== 'object' || value === null)
    fail('Frontmatter must contain plain data')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null)
    fail('Frontmatter must contain plain data')
  /** @type {Record<string, any>} */
  const result = {}
  for (const key of Object.keys(value)) {
    if (forbiddenKeys.has(key)) fail('Unsafe frontmatter property')
    budget.bytes += new TextEncoder().encode(key).length
    if (budget.bytes > STATIC_LIMITS.maxCodeBytes)
      fail('Frontmatter exceeds the byte limit')
    result[key] = cloneData(value[key], budget, depth + 1, preserveDates)
  }
  return result
}

/** @param {string} value @param {boolean} image */
function safeUrl(value, image) {
  // eslint-disable-next-line no-control-regex -- Browsers normalize these characters in URL schemes.
  if (/[\u0000-\u001f\u007f]/u.test(value))
    fail('Control characters are not allowed in URLs')
  let url
  try {
    url = new URL(value.trim(), 'https://mdx-content.invalid/')
  } catch {
    return fail('Invalid URL')
  }
  const protocols = image
    ? ['https:', 'http:']
    : ['https:', 'http:', 'mailto:', 'tel:']
  if (!protocols.includes(url.protocol)) fail('URL protocol is not allowed')
  if (
    value.startsWith('#') &&
    value.length > 1 &&
    !value.startsWith('#mdx-content-')
  ) {
    return `#mdx-content-${value.slice(1)}`
  }
  return value.trim()
}

/** @param {string} tag @param {Record<string, any>} attributes */
function sanitizeElement(tag, attributes) {
  if (!tags.has(tag)) fail(`Element "${tag}" is not allowed in strict mode`)
  /** @type {Record<string, string | number | boolean>} */
  const result = {}
  if (Object.keys(attributes).length > 64) fail('Too many element attributes')
  for (let [key, value] of Object.entries(attributes)) {
    if (key === 'class') key = 'className'
    if (
      forbiddenKeys.has(key) ||
      /^on/i.test(key) ||
      !(
        globalAttributes.has(key) ||
        tagAttributes[tag]?.has(key) ||
        /^(?:aria|data)-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(key)
      )
    )
      fail(`Attribute "${key}" is not allowed in strict mode`)
    if (
      !['string', 'number', 'boolean'].includes(typeof value) ||
      (typeof value === 'number' && !Number.isFinite(value))
    )
      fail('Attributes must be literal data')
    if (key === 'href' || key === 'src') {
      if (typeof value !== 'string') fail('URL attributes must be strings')
      value = safeUrl(value, key === 'src')
    }
    if (key === 'id') {
      if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value))
        fail('Invalid element id')
      if (!value.startsWith('mdx-content-')) value = `mdx-content-${value}`
    }
    if (key === 'target' && value !== '_blank' && value !== '_self')
      fail('Invalid link target')
    if (key === 'dir' && !['ltr', 'rtl', 'auto'].includes(value))
      fail('Invalid text direction')
    if (
      [
        'width',
        'height',
        'colSpan',
        'rowSpan',
        'span',
        'start',
        'value',
        'tabIndex',
      ].includes(key)
    ) {
      const number = Number(value)
      if (
        !Number.isSafeInteger(number) ||
        Math.abs(number) > 16384 ||
        (key === 'tabIndex' && number !== 0 && number !== -1)
      )
        fail('Invalid numeric attribute')
      value = number
    }
    result[key] = value
  }
  if (tag === 'a' && result.target === '_blank') {
    const rel = typeof result.rel === 'string' ? result.rel.split(/\s+/) : []
    result.rel = [...new Set([...rel, 'noopener', 'noreferrer'])].join(' ')
  }
  return result
}

/**
 * @typedef {{tag: string, props: Record<string, string | number | boolean>, children: StaticNode[]}} StaticElement
 * @typedef {string | StaticElement} StaticNode
 */

/**
 * @param {any} node
 * @param {ReturnType<typeof createBudget>} budget
 * @param {number} depth
 * @returns {StaticNode}
 */
function validateNode(node, budget, depth) {
  consume(budget, depth)
  if (typeof node === 'string') return node
  if (
    !node ||
    typeof node !== 'object' ||
    Array.isArray(node) ||
    typeof node.tag !== 'string' ||
    !node.props ||
    typeof node.props !== 'object' ||
    Array.isArray(node.props) ||
    !Array.isArray(node.children)
  )
    fail('Invalid static element')
  const props = sanitizeElement(node.tag, node.props)
  if (voidTags.has(node.tag) && node.children.length)
    fail('Void elements cannot have children')
  return {
    tag: node.tag,
    props,
    children: node.children.map((/** @type {any} */ child) =>
      validateNode(child, budget, depth + 1),
    ),
  }
}

/** @param {string} code */
function parseStaticCode(code) {
  if (typeof code !== 'string' || !code.startsWith(STATIC_PREFIX)) {
    return fail(
      'Executable code requires explicit {trusted: true} at the client. Use strict bundleMDX output for untrusted content.',
    )
  }
  checkBytes(code, STATIC_LIMITS.maxCodeBytes)
  let packet
  try {
    packet = JSON.parse(code.slice(STATIC_PREFIX.length))
  } catch {
    return fail('Invalid static artifact')
  }
  if (
    packet?.version !== 1 ||
    !Array.isArray(packet.tree) ||
    !packet.frontmatter ||
    typeof packet.frontmatter !== 'object' ||
    Array.isArray(packet.frontmatter)
  )
    fail('Invalid static artifact')
  const budget = createBudget()
  const frontmatter = cloneData(packet.frontmatter, budget)
  const tree = packet.tree.map((/** @type {any} */ node) =>
    validateNode(node, budget, 0),
  )
  return {frontmatter, tree}
}

/**
 * @param {string} code
 * @param {{jsx: (type: any, props: any, key?: any) => any, Fragment: any}} runtime
 */
function createStaticExport(code, runtime) {
  const packet = parseStaticCode(code)
  /** @param {Record<string, any>} [props] */
  function StaticMDX(props = {}) {
    const components = Object.hasOwn(props, 'components')
      ? (props.components ?? {})
      : {}
    /** @param {StaticNode} node @param {number} key @returns {any} */
    function render(node, key) {
      if (typeof node === 'string') return node
      const replacement = Object.hasOwn(components, node.tag)
        ? components[node.tag]
        : node.tag
      if (typeof replacement === 'string')
        sanitizeElement(replacement, node.props)
      const children = node.children.map(render)
      return runtime.jsx(
        replacement,
        {
          ...node.props,
          ...(children.length
            ? {children: children.length === 1 ? children[0] : children}
            : {}),
        },
        key,
      )
    }
    const children = packet.tree.map(render)
    const content = runtime.jsx(runtime.Fragment, {children})
    if (!Object.hasOwn(components, 'wrapper')) return content
    const wrapper = components.wrapper
    if (typeof wrapper === 'string') sanitizeElement(wrapper, {})
    return runtime.jsx(wrapper, {children: content})
  }
  return {default: StaticMDX, frontmatter: packet.frontmatter}
}

export {
  STATIC_PREFIX,
  STATIC_LIMITS,
  checkBytes,
  createBudget,
  consume,
  cloneData,
  forbiddenKeys,
  sanitizeElement,
  parseStaticCode,
  createStaticExport,
  fail,
}
