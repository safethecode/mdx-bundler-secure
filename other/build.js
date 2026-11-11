import {copyFile, mkdir, readdir, rm, writeFile} from 'node:fs/promises'
import {build} from 'esbuild'

await rm('dist', {recursive: true, force: true})
await mkdir('dist', {recursive: true})
await build({
  entryPoints: [
    'src/index.js',
    'src/security.js',
    'src/client/index.js',
    'src/client/react.js',
    'src/client/jsx.js',
  ],
  outbase: 'src',
  outdir: 'dist',
  platform: 'node',
  format: 'cjs',
  target: 'node22',
})
await copyFile('src/dirname-messed-up.cjs', 'dist/dirname-messed-up.cjs')
for (const name of await readdir('src')) {
  if (name.endsWith('.d.ts')) await copyFile(`src/${name}`, `dist/${name}`)
}
await writeFile('dist/package.json', JSON.stringify({type: 'commonjs'}))
