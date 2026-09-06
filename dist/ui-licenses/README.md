# UI license supplements

The webpack collector reads LICENSE, COPYING, NOTICE, COPYRIGHT and AUTHORS
files from packages that contribute modules to the UI bundle. It also accepts
a complete MIT license section in a package README.

`overrides.json` covers seven exact package versions whose npm archives omit
a separate license file. Each entry binds a supplement to the locked npm
archive integrity, the supplement's SHA-256, and primary-source URLs. A changed
version, archive or text must be reviewed before updating the entry.

- `@ant-design/icons-svg`, `@umijs/hooks` and `@umijs/use-request`: original
  repository LICENSE at the npm publication's recorded Git commit.
- `format`, `toggle-selection` and `umi-request`: the published package
  explicitly selects MIT. Supplements retain available source/README
  attribution and include the standard MIT permission and disclaimer text.
  They do not invent a copyright holder or year where one was not supplied.
- `intersection-observer`: the package's Google copyright header and the full
  W3C Software and Document License, 2015 version.

The `basis` and `sources` fields distinguish original license copies from
standard license text combined with available attribution. Preserve that
distinction during legal review. Do not substitute an unrelated current
repository LICENSE for an older published package.

After changing dependencies or supplements, run `npm ci`, `npm run build` and
`npm run check:notices` in `ui/`. Review `ui/dist/legal/components.json` and
`THIRD-PARTY-NOTICES.txt`, including packages used only in dynamic chunks.
Missing material fails the build; do not add a blanket license fallback.

This collection is an engineering inventory. Review separately any embedded
third-party source, manually copied assets, exceptions or dual-license choices;
package-level metadata does not complete that review. These third-party texts
retain their original licensing independently of MassDB's pending new-code
licensing decision.
