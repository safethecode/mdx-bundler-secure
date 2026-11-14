import {parentPort, workerData} from 'node:worker_threads'
import {compileStatic} from './static-compiler.js'

async function main() {
  if (!parentPort) throw new Error('Static compiler must run in its worker')
  try {
    parentPort.postMessage({ok: true, result: await compileStatic(workerData)})
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      error:
        error instanceof Error ? error.message : 'Static compilation failed',
    })
  }
}

void main()
