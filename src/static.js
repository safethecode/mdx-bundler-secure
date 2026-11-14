import fs from 'node:fs/promises'
import path from 'node:path'
import yaml from 'js-yaml'
import {
  STATIC_LIMITS,
  checkBytes,
  cloneData,
  createBudget,
  fail,
} from './static-policy.js'
import {runStaticCompilation, boundedLimit} from './static-runner.js'

/** @param {string} file @param {string} cwd @param {number} maximum */
async function readBoundedFile(file, cwd, maximum) {
  const root = await fs.realpath(cwd)
  const resolved = await fs.realpath(path.resolve(root, file))
  const relative = path.relative(root, resolved)
  if (
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  )
    fail('File is outside the allowed cwd')
  if (!['.md', '.mdx'].includes(path.extname(resolved).toLowerCase()))
    fail('Strict mode only opens .md and .mdx files')
  const handle = await fs.open(resolved, 'r')
  try {
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size > maximum)
      fail('Source file exceeds the byte limit or is not a regular file')
    const buffer = Buffer.alloc(maximum + 1)
    const {bytesRead} = await handle.read(buffer, 0, buffer.length, 0)
    if (bytesRead > maximum) fail('Source file exceeds the byte limit')
    return new TextDecoder('utf-8', {fatal: true}).decode(
      buffer.subarray(0, bytesRead),
    )
  } finally {
    await handle.close()
  }
}

/**
 * @template {{[key: string]: any}} Frontmatter
 * @param {import('./types').BundleMDX<Frontmatter>} options
 * @returns {Promise<import('./types').BundleMDXResult<Frontmatter>>}
 */
async function bundleStaticMDX(options) {
  for (const key of [
    'files',
    'globals',
    'mdxOptions',
    'esbuildOptions',
    'grayMatterOptions',
    'jsxConfig',
    'bundleDirectory',
    'bundlePath',
  ]) {
    if (
      Object.hasOwn(options, key) &&
      /** @type {any} */ (options)[key] !== undefined
    ) {
      fail(
        `${key} requires explicit trusted: true; strict mode does not load modules, plugins, or custom engines`,
      )
    }
  }
  if (options.trusted !== undefined && typeof options.trusted !== 'boolean')
    fail('trusted must be a boolean')
  if (options.blockDangerousJS === false)
    fail('Disabling JavaScript checks requires explicit trusted: true')
  if (options.blockJS !== undefined && typeof options.blockJS !== 'boolean')
    fail('blockJS must be a boolean')
  const requested = options.securityLimits ?? {}
  for (const key of Object.keys(requested)) {
    if (!['maxSourceBytes', 'maxNodes', 'maxDepth', 'timeoutMs'].includes(key))
      fail('Unknown security limit')
  }
  const limits = {
    maxSourceBytes: boundedLimit(
      requested.maxSourceBytes,
      STATIC_LIMITS.maxSourceBytes,
      'maxSourceBytes',
    ),
    maxNodes: boundedLimit(
      requested.maxNodes,
      STATIC_LIMITS.maxNodes,
      'maxNodes',
    ),
    maxDepth: boundedLimit(
      requested.maxDepth,
      STATIC_LIMITS.maxDepth,
      'maxDepth',
    ),
    timeoutMs: boundedLimit(
      requested.timeoutMs,
      STATIC_LIMITS.timeoutMs,
      'timeoutMs',
    ),
  }
  let source
  if (options.source !== undefined) {
    if (options.file !== undefined) fail('Use source or file, not both')
    const value =
      typeof options.source === 'string' ? options.source : options.source.value
    if (typeof value === 'string') {
      checkBytes(value, limits.maxSourceBytes)
      source = value
    } else if (value instanceof Uint8Array) {
      if (value.byteLength > limits.maxSourceBytes)
        fail('Source exceeds the byte limit')
      source = new TextDecoder('utf-8', {fatal: true}).decode(value)
    } else return fail('source must contain a string or Uint8Array')
  } else if (typeof options.file === 'string') {
    source = await readBoundedFile(
      options.file,
      options.cwd ?? process.cwd(),
      limits.maxSourceBytes,
    )
  } else return fail('source or file must be provided')
  const result = await runStaticCompilation(
    {source, blockJS: options.blockJS === true, limits},
    limits.timeoutMs,
  )
  result.matter.stringify = (language = 'yaml') => {
    const data = cloneData(result.frontmatter, createBudget(), 0, true)
    if (language === 'json')
      return `---json\n${JSON.stringify(data)}\n---\n${result.matter.content}`
    if (language !== 'yaml' && language !== 'yml')
      return fail('Static matter.stringify supports YAML and JSON')
    return `---\n${yaml.safeDump(data)}---\n${result.matter.content}`
  }
  return result
}

export {bundleStaticMDX}
