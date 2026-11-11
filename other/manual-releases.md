# Releases

1. Update `package.json`, `package-lock.json`, and `CHANGELOG.md`. Use a major
   version when changing supported Node.js versions or security option behavior.
2. Run `npm ci` and `npm run validate`.
3. Inspect `npm pack --dry-run`, then test the tarball in a clean consumer project.
4. Commit with an appropriate `fix:` / `feat:` message and push to `main`.
5. Create and push a matching version tag, for example `v2.0.0`.
6. Verify the validation workflow, npm version/dist-tag, and GitHub release.

The release job uses npm trusted publishing with provenance. Configure the npm
package's trusted publisher for GitHub Actions:

- Owner: `safethecode`
- Repository: `mdx-bundler-secure`
- Workflow filename: `validate.yml`
- Environment: leave empty (the workflow does not use a GitHub environment).

This one-time package setting requires an authenticated npm maintainer. See
[npm's trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/).
After configuring it, rerun a failed tag workflow if needed.

For a local manual release, authenticate using `npm login`, run validation, and
publish with `npm publish --access public`. Create the matching GitHub release
after confirming the registry version. A tag workflow accepts an already
published version only if its `gitHead` matches the tagged commit.
