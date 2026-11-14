import yaml from 'js-yaml'
import {parse as parseYaml} from 'yaml'
import {parse as parseToml} from 'smol-toml'
import {
  STATIC_PREFIX,
  STATIC_LIMITS,
  createBudget,
  consume,
  cloneData,
  forbiddenKeys,
  sanitizeElement,
  checkBytes,
  parseStaticCode,
  fail,
} from './static-policy.js'

/** @param {string} source */
function readFrontmatter(source) {
  const input = source.replace(/^\uFEFF/u, '')
  const lines = input.split('\n')
  const header = /^(---|\+\+\+)([A-Za-z]*)[ \t]*\r?$/.exec(lines[0])
  if (!header || lines.length === 1) {
    return {
      data: {},
      exported: {},
      content: input,
      matter: '',
      language: 'yaml',
    }
  }
  const fence = header[1]
  const language = (
    header[2] || (fence === '+++' ? 'toml' : 'yaml')
  ).toLowerCase()
  if (language === 'js' || language === 'javascript')
    fail('JavaScript frontmatter is disabled')
  if (!['yaml', 'yml', 'toml', 'json'].includes(language))
    fail('Unsupported frontmatter format')
  const end = lines.findIndex(
    (line, index) => index > 0 && line.trim() === fence,
  )
  if (end === -1) fail('Frontmatter closing delimiter is missing')
  const matter = lines.slice(1, end).join('\n')
  const content = lines.slice(end + 1).join('\n')
  let data, exported
  if (language === 'toml') {
    data = exported = parseToml(matter, {
      maxDepth: STATIC_LIMITS.maxDepth,
      unsafeKeyBehaviour: 'throw',
    })
  } else if (language === 'json') {
    data = exported = JSON.parse(matter)
  } else {
    exported = parseYaml(matter, {maxAliasCount: 50}) ?? {}
    data = yaml.safeLoad(matter) ?? {}
  }
  if (
    !data ||
    typeof data !== 'object' ||
    Array.isArray(data) ||
    !exported ||
    typeof exported !== 'object' ||
    Array.isArray(exported)
  )
    fail('Frontmatter must be a mapping')
  return {data, exported, content, matter, language}
}

/**
 * This is an interpreter for a small data syntax, not a JavaScript evaluator.
 * Calls, operators, functions, declarations, globals, and prototype access have
 * no implementation here and are rejected before any rendering occurs.
 * @param {any} expression @param {any} frontmatter
 * @param {ReturnType<typeof createBudget>} budget @param {number} [depth]
 * @returns {any}
 */
function readDataExpression(expression, frontmatter, budget, depth = 0) {
  consume(budget, depth)
  if (
    expression?.type === 'Literal' &&
    (expression.value === null ||
      ['string', 'number', 'boolean'].includes(typeof expression.value))
  ) {
    return cloneData(expression.value, budget, depth + 1)
  }
  if (expression?.type === 'Identifier' && expression.name === 'frontmatter')
    return frontmatter
  if (expression?.type === 'ArrayExpression') {
    return expression.elements.map((/** @type {any} */ item) =>
      item === null
        ? null
        : readDataExpression(item, frontmatter, budget, depth + 1),
    )
  }
  if (expression?.type === 'MemberExpression' && !expression.optional) {
    const key = expression.computed
      ? expression.property?.type === 'Literal'
        ? expression.property.value
        : null
      : expression.property?.type === 'Identifier'
        ? expression.property.name
        : null
    if (
      !['string', 'number'].includes(typeof key) ||
      forbiddenKeys.has(String(key))
    )
      fail('Unsafe frontmatter property reference')
    const object = readDataExpression(
      expression.object,
      frontmatter,
      budget,
      depth + 1,
    )
    if (!object || typeof object !== 'object' || !Object.hasOwn(object, key))
      fail('Unknown frontmatter property')
    return object[key]
  }
  return fail(
    'Strict mode allows only literal values and frontmatter property references. Executable MDX requires trusted: true.',
  )
}

/** @param {any} node @param {any} frontmatter @param {ReturnType<typeof createBudget>} budget */
function expressionValue(node, frontmatter, budget) {
  const body = node.data?.estree?.body
  if (Array.isArray(body) && body.length === 0) return null
  if (
    !Array.isArray(body) ||
    body.length !== 1 ||
    body[0].type !== 'ExpressionStatement'
  )
    fail('Invalid data expression')
  return readDataExpression(body[0].expression, frontmatter, budget)
}

/** @param {any} value @param {ReturnType<typeof createBudget>} budget @param {number} depth @returns {import('./static-policy.js').StaticNode[]} */
function textValue(value, budget, depth) {
  consume(budget, depth)
  if (value === null || typeof value === 'boolean') return []
  if (
    typeof value === 'string' ||
    (typeof value === 'number' && Number.isFinite(value))
  )
    return [cloneData(String(value), budget, depth + 1)]
  if (Array.isArray(value))
    return value.flatMap(item => textValue(item, budget, depth + 1))
  return fail('Only primitive frontmatter values can be rendered as text')
}

/**
 * @param {{source: string, blockJS: boolean, limits: {maxNodes: number, maxDepth: number}}} input
 */
async function compileStatic(input) {
  const matter = readFrontmatter(input.source)
  const frontmatter = cloneData(
    matter.data,
    createBudget(input.limits),
    0,
    true,
  )
  const exported = cloneData(matter.exported, createBudget(input.limits))
  const {createProcessor} = await import('@mdx-js/mdx')
  // Parse only: no caller plugins, module resolution, compilation, or evaluate().
  const ast = createProcessor({format: 'mdx'}).parse(matter.content)
  const definitions = new Map()
  for (const node of ast.children) {
    if (node.type === 'definition') definitions.set(node.identifier, node)
  }
  const budget = createBudget(input.limits)
  /** @param {string} tag @param {Record<string, any>} props @param {import('./static-policy.js').StaticNode[]} children @returns {import('./static-policy.js').StaticNode[]} */
  const element = (tag, props, children) => [
    {tag, props: sanitizeElement(tag, props), children},
  ]
  /** @param {any[]} nodes @param {number} depth @returns {import('./static-policy.js').StaticNode[]} */
  const children = (nodes, depth) => nodes.flatMap(node => convert(node, depth))
  /** @param {any} node @param {number} depth @returns {import('./static-policy.js').StaticNode[]} */
  function convert(node, depth) {
    consume(budget, depth)
    switch (node.type) {
      case 'root':
        return children(node.children, depth + 1)
      case 'text':
        return [node.value]
      case 'paragraph':
        return element('p', {}, children(node.children, depth + 1))
      case 'heading':
        return element(`h${node.depth}`, {}, children(node.children, depth + 1))
      case 'emphasis':
        return element('em', {}, children(node.children, depth + 1))
      case 'strong':
        return element('strong', {}, children(node.children, depth + 1))
      case 'delete':
        return element('del', {}, children(node.children, depth + 1))
      case 'blockquote':
        return element('blockquote', {}, children(node.children, depth + 1))
      case 'thematicBreak':
        return element('hr', {}, [])
      case 'break':
        return element('br', {}, [])
      case 'inlineCode':
        return element('code', {}, [node.value])
      case 'code': {
        const props =
          node.lang && /^[A-Za-z0-9_+-]{1,64}$/.test(node.lang)
            ? {className: `language-${node.lang}`}
            : {}
        return element('pre', {}, element('code', props, [node.value + '\n']))
      }
      case 'list':
        return element(
          node.ordered ? 'ol' : 'ul',
          node.ordered && node.start !== 1 ? {start: node.start} : {},
          children(node.children, depth + 1),
        )
      case 'listItem': {
        const content = node.children.flatMap((/** @type {any} */ child) =>
          !node.spread && child.type === 'paragraph'
            ? children(child.children, depth + 1)
            : convert(child, depth + 1),
        )
        return element('li', {}, content)
      }
      case 'definition':
        return []
      case 'link':
        return element(
          'a',
          {href: node.url, ...(node.title ? {title: node.title} : {})},
          children(node.children, depth + 1),
        )
      case 'image':
        return element(
          'img',
          {
            src: node.url,
            alt: node.alt ?? '',
            ...(node.title ? {title: node.title} : {}),
          },
          [],
        )
      case 'linkReference':
      case 'imageReference': {
        const definition = definitions.get(node.identifier)
        if (!definition) fail('Unresolved Markdown reference')
        return convert(
          {
            ...node,
            type: node.type === 'linkReference' ? 'link' : 'image',
            url: definition.url,
            title: definition.title,
          },
          depth + 1,
        )
      }
      case 'mdxFlowExpression':
      case 'mdxTextExpression':
        return input.blockJS
          ? []
          : textValue(
              expressionValue(node, exported, budget),
              budget,
              depth + 1,
            )
      case 'mdxjsEsm':
        if (input.blockJS) return []
        return fail(
          'Imports and exports require trusted: true; strict mode does not resolve files or packages',
        )
      case 'mdxJsxFlowElement':
      case 'mdxJsxTextElement': {
        if (node.name === null) return children(node.children, depth + 1)
        /** @type {Record<string, any>} */
        const props = Object.create(null)
        for (const attribute of node.attributes) {
          if (attribute.type !== 'mdxJsxAttribute') {
            if (input.blockJS) continue
            return fail('JSX spreads are not allowed in strict mode')
          }
          const value = attribute.value
          if (value && typeof value === 'object') {
            if (input.blockJS) continue
            props[attribute.name] = expressionValue(value, exported, budget)
          } else {
            props[attribute.name] = value === null ? true : value
          }
        }
        return element(node.name, props, children(node.children, depth + 1))
      }
      default:
        return fail(`Unsupported Markdown node: ${node.type}`)
    }
  }
  const tree = convert(ast, 0)
  const escapes = /** @type {Record<string, string>} */ ({
    '<': '\\u003c',
    '>': '\\u003e',
    '&': '\\u0026',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029',
  })
  const code =
    STATIC_PREFIX +
    JSON.stringify({version: 1, frontmatter: exported, tree}).replace(
      /[<>&\u2028\u2029]/gu,
      character => escapes[character],
    )
  checkBytes(code, STATIC_LIMITS.maxCodeBytes)
  parseStaticCode(code)
  return {
    code,
    frontmatter,
    errors: [],
    matter: {
      data: frontmatter,
      content: matter.content,
      orig: input.source,
      language: matter.language,
      matter: matter.matter,
    },
  }
}

export {compileStatic}
