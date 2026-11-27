# Publishing a version of Multisig

Same flow as Ghostly Chess's `docs/PUBLISHING.md`. Nothing here has been published yet.

## Once, before the first version

1. Create the GitHub repository and set `REPO` in `scripts/bundle.mjs` and `OWNER` in `ghostly-app.json`.
2. Make a publisher key with the Ghostly CLI. Keep the `.key` file outside the repository (`.gitignore` refuses
   `*.key`). Put its public key in `PUBLISHER` in `scripts/bundle.mjs`.
3. `npm test`: the bundle test stops flagging placeholders.

## Each version

1. Bump `version` in `ghostly-app.json` and `package.json`; move "Unreleased" in `CHANGES.md` under it.
2. Build and stage:
   ```sh
   npm ci && npm run typecheck && npm test && npm run test:browser
   npm run build && npm run digest
   npm run check:bundle -- --expect <sequence>
   npm run stage                       # release/: index.html, icon.png, ghostly-app.json
   ```
3. Sign (the key holder): `ghostly app publish release --key <key> --out app.ghostlyapp --sequence <n>`, then
   `ghostly app verify app.ghostlyapp` and `npm run check:bundle`.
4. Commit `app.ghostlyapp`, push to `main`, then `npm run check:bundle -- --listing` prints the store's listing.json.
5. Open a pull request on the Ghostly store with that listing.

Never run `ghostly app publish` on the repository itself: it bundles every file in the folder.
