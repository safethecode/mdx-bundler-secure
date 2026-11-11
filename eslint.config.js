import js from '@eslint/js'
import globals from 'globals'

export default [
  {ignores: ['node_modules/**', 'dist/**', 'coverage/**', 'output/**']},
  js.configs.recommended,
  {
    languageOptions: {globals: {...globals.node, ...globals.browser}},
    linterOptions: {reportUnusedDisableDirectives: 'error'},
    rules: {
      'no-unused-vars': ['error', {args: 'none', caughtErrors: 'none'}],
      'no-eval': 'error',
      'no-new-func': 'error',
    },
  },
  {files: ['client/*.js'], languageOptions: {sourceType: 'commonjs'}},
]
