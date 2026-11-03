# v1.7.0 作業記録

各タスクの完了時に、次の形式で追記してください。完了報告書の材料になります。このファイルはコミットされるので、作業者のユーザー名・ローカルパス・ツールの製品名は書かないでください。

```
## T00 <タスク名>  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <指示書に書かれていなかったことをどう決めたか>
- 未解決: <あれば>
```

---

## T01 バージョン比較の作り直し  (2026-11-03 06:19)
- 変更ファイル: `src/security/version-matcher.ts`, `scripts/validate-advisories.mjs`, `tests/version-check.test.ts`
- 判断したこと:
  - ワイルドカード判定は比較対象のトークン全体が `^\d+(\.\d+)*\.(x|\*)$`（大文字小文字不問）に一致する場合のみに限定し、`22.0.0-next.0` 等に `.x` が部分文字列として含まれても誤判定しないようにした。またプレフィックスの全数値要素の一致を必須とした（`4.3.x` は major=4 かつ minor=3）。
  - SemVer 2.0 プレリリース識別子（`alpha`, `beta`, `rc`, `next`, `pre`, `preview`, `dev`, `canary`, `nightly`, `experimental` および `.` 区切りの後続識別子）とビルドメタデータ（`+...`）を解析し、SemVer 2.0 §11 の順序規則（プレリリース付き < 通常版、数値識別子は数値比較、非数値は ASCII 辞書順、`rc2 < rc10` のような英字+数字連結の分割比較）を実装した。
  - Linux ディストリビューションのパッケージ版サフィックスは従来どおりプレリリース扱いせず数値部分で比較し、4要素以上の数値バージョンも不足分を 0 埋めして比較できるようにした。
  - `scripts/validate-advisories.mjs` の `isValidRange` で `||` と `,` で分割したすべての節を `version-matcher.ts` と同じ規則で検証し、`>= 1.0.0-nxt` のような不正な識別子を検出できるようにした。
- 未解決: なし

## T02 DB に依存しないテストへの整理  (2026-11-03 12:52)
- 変更ファイル: `tests/fixtures/advisory-db.fixture.json`, `tests/advisory-db-invariants.test.ts`, `tests/version-check.test.ts`, `tests/advisory.test.ts`, `tests/review-v1.6.5-acceptance.test.ts`
- 判断したこと:
  - 現行の `src/detection/advisory-db.json` のスナップショットを `tests/fixtures/advisory-db.fixture.json` として複製し、`tests/version-check.test.ts`、`tests/advisory.test.ts`、`tests/review-v1.6.5-acceptance.test.ts` で特定の CVE・件数・推奨版・EOL を検証している `matchOfflineAdvisories` 呼び出しに `fixtureDb`（`dbOverride`）を渡す形に移行した。
  - 同梱 `src/detection/advisory-db.json` の検証は新設した `tests/advisory-db-invariants.test.ts` に集約し、件数や特定 CVE の有無に依存しない不変条件（`schemaVersion: "2.2"`、全 14 製品の存在、`minExtensionVersion <= manifest.version`、全エントリの必須項目と `isValidRange` / `validateDb` による構文検証、壊れたトークン `>= 1.0.0-nxt` の拒否検証）のみを検査する構成にした。
  - エントリ半減テスト等で `libraries` のみ差し替えられた場合でも構造・範囲の不変条件を検証できるよう、`validateDb` 呼び出し時には `integrity` を除外して検証するようにした。
- 未解決: なし


