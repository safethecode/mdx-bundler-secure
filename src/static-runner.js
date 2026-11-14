import {Worker} from 'node:worker_threads'
import workerPath from './worker-path.cjs'
import {fail} from './static-policy.js'

const MAX_WORKERS = 2
const MAX_PENDING = 8
let active = 0
/** @type {Array<() => void>} */
const pending = []

function drain() {
  while (active < MAX_WORKERS && pending.length) pending.shift()?.()
}

/** @param {any} input @param {number} timeoutMs @returns {Promise<any>} */
function runStaticCompilation(input, timeoutMs) {
  if (active >= MAX_WORKERS && pending.length >= MAX_PENDING) {
    return Promise.reject(
      new Error('[mdx-bundler-secure] Static compiler is busy; retry later'),
    )
  }
  return new Promise((resolve, reject) => {
    let finished = false
    let started = false
    /** @type {Worker | undefined} */
    let worker
    const timer = setTimeout(
      () =>
        finish(new Error('[mdx-bundler-secure] Static compilation timed out')),
      timeoutMs,
    )
    /** @param {Error | null} error @param {any} [value] */
    function finish(error, value) {
      if (finished) return
      finished = true
      clearTimeout(timer)
      const index = pending.indexOf(start)
      if (index !== -1) pending.splice(index, 1)
      void (
        worker ? worker.terminate().catch(() => undefined) : Promise.resolve()
      ).then(() => {
        if (started) active--
        drain()
        if (error) reject(error)
        else resolve(value)
      })
    }
    function start() {
      if (finished) return
      active++
      started = true
      try {
        worker = new Worker(workerPath, {
          workerData: input,
          execArgv: [],
          // No application credentials or NODE_OPTIONS are needed by the parser.
          env: process.env.NODE_V8_COVERAGE
            ? {NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE}
            : {},
          resourceLimits: {
            maxOldGenerationSizeMb: 64,
            maxYoungGenerationSizeMb: 16,
            stackSizeMb: 4,
          },
        })
        worker.once('message', message => {
          if (message?.ok === true && message.result)
            finish(null, message.result)
          else
            finish(
              new Error(
                message?.error ??
                  '[mdx-bundler-secure] Static compilation failed',
              ),
            )
        })
        worker.once('error', error =>
          finish(
            new Error(
              `[mdx-bundler-secure] Static parser worker failed or exceeded its memory limit: ${error.message}`,
            ),
          ),
        )
        worker.once('exit', () =>
          finish(
            new Error(
              '[mdx-bundler-secure] Static parser worker exited before returning data',
            ),
          ),
        )
      } catch (error) {
        finish(
          error instanceof Error
            ? error
            : new Error('Static parser worker could not start'),
        )
      }
    }
    if (active < MAX_WORKERS) start()
    else pending.push(start)
  })
}

/** @param {unknown} value @param {number} maximum @param {string} name */
function boundedLimit(value, maximum, name) {
  if (value === undefined) return maximum
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    return fail(`${name} must be an integer between 1 and ${maximum}`)
  }
  return value
}

export {runStaticCompilation, boundedLimit}
