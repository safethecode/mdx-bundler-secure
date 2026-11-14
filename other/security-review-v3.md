# Version 3 security boundary review — 2026-11-14

Baseline: `mdx-bundler-secure` 2.0.0, commit
`0f76245418883b5e0d691caa0254efd1e8b6b8af`.

The 2.x dependency audit found no known vulnerable entries in its resolved tree.
That result did not establish the safety of executing authored MDX. This release
addresses the separately confirmed code-level boundaries through a restricted,
data-only default. The legacy executable compiler requires explicit trust.

## Changes by boundary

| Previously confirmed risk                                                  | 3.x default behavior                                                                                                                                                                                                                     | Verification                                                                                                                                                  |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pattern matching and shadowed globals did not isolate arbitrary JavaScript | Only literal values and own frontmatter references are interpreted. No calls, functions, operators, global identifiers, or prototype access are implemented. Clients construct JSX from validated data instead of evaluating JavaScript. | Known unsafe expressions are rejected; raw code is rejected by default; literal/data rendering works.                                                         |
| Source imports could read JSON outside the assumed content directory       | Strict content does not resolve imports, packages, or source files. Explicit entry files use real-path checks inside `cwd` and accept only Markdown extensions.                                                                          | Relative, absolute, builtin, and package module statements reject before resolution. Explicit entry and symlink path tests enforce the root.                  |
| Static script tags survived expression stripping                           | A fixed content element/attribute/URL policy is checked at both producer and consumer. Scripts, embedded documents, event handlers, inline styles, raw HTML insertion, and unsafe protocols are rejected.                                | Forbidden source tags/attributes/URLs and forged client artifacts reject. Code text remains escaped; safe Markdown and static JSX render.                     |
| Source programs could block the evaluation process indefinitely            | The default client never evaluates a program. Parsing uses bounded disposable workers, a queue, deadlines, V8 heap controls, byte ceilings, and depth/node budgets.                                                                      | Deadline and overload tests use benign input, verify rejection and slot recovery, and check client data budgets. No long-running source program is evaluated. |

## Strict implementation

- `src/static-compiler.js` parses MDX syntax and converts the accepted subset to
  a static element/data tree. It does not run caller plugins, resolve modules, or
  call the MDX evaluator/compiler on authored programs.
- `src/static-policy.js` is shared with browser clients. It validates schema,
  data keys, size/depth/node budgets, tags, attributes, and URL schemes before
  rendering. It contains no dynamic-code evaluation or Node-specific imports.
- `src/static-runner.js` manages two active workers and at most eight pending
  jobs. The 5-second default deadline includes queue time; failure terminates
  the worker and releases its slot. Callers can lower supported limits.
- `src/static.js` bounds UTF-8 input and explicit file reads. Source-authored
  imports do not reach the filesystem. Entry paths and the content directory
  remain host-controlled and should not be writable by untrusted users.
- The React and generic JSX clients accept static artifacts by default. Old/raw
  JavaScript requires an explicit client opt-in independent of compiler options.

The default source limit is 256 KiB; artifacts are limited to 2 MiB, with a
10,000-node and 64-level budget. Worker V8 old/young heaps are limited to
64/16 MiB. The limits are fixed upper bounds for accepted strict-mode options;
applications may lower them. These bounds are enforced again on decoded client
artifacts where applicable.

## Remaining trust assumptions

1. `trusted: true` deliberately enables ordinary application code with ordinary
   application privileges. The legacy regex filters do not make it a sandbox.
   Strict limits and static HTML policy do not apply to that mode.
2. Options, plugins, custom engines, JSX runtimes, globals, host component
   implementations, and entry paths come from trusted application code. Do not
   derive them from an untrusted request object or use the trusted flag to bypass
   validation errors for external authors.
3. Worker heap/deadline controls protect parser availability; workers are not OS
   security sandboxes. Native allocations, other application work, and aggregate
   service load need request/rate/concurrency and OS/container resource limits.
   [Node's worker documentation](https://nodejs.org/api/worker_threads.html#new-workerfilename-options)
   describes the scope of worker resource limits.
4. A host component can perform its own I/O or unsafe rendering. Its security
   remains the host application's responsibility. The static content policy
   controls source-authored elements and props, not arbitrary host programs.
5. Transport artifacts as escaped JSON. Do not insert authored data as raw HTML.
   Keep Node.js, the selected UI runtime, esbuild, and downstream dependencies
   patched independently of this package's own audit results.

## Verification

The suite separates trusted compatibility tests from strict security tests.
Known unsafe cases are asserted to reject before evaluation. Worker deadline
and overload checks use benign Markdown. There is no additional attack
execution in the release verification.

Required checks are `npm run validate`, full and production dependency audits,
Node.js 22/24/26 test runs, browser-client bundling, and a fresh package consumer
using the minimum esbuild peer with strict NodeNext declaration checking.
Dependency results are a dated advisory snapshot, not a proof that all possible
defects have been eliminated.

Verified locally for this release:

- Node.js 22, 24, and 26: 128 tests passed on each runtime.
- `npm ci` and `npm run validate`: lint, source type checks, tests, build,
  consumer declaration checks, packaged runtime checks, and full audit passed.
- Full and production dependency audits: zero known vulnerable entries.
- Both browser client entry points bundled without Node worker/filesystem imports.
- A fresh tarball consumer using esbuild 0.25.0 passed strict and trusted API
  checks, worker-asset resolution, CommonJS/ESM checks, strict NodeNext type
  checking with `skipLibCheck: false`, and a clean dependency audit.
