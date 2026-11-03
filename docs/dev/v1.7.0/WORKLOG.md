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

## T03 fixStatus・KEV・重大度 4 段階の表示  (2026-11-03 13:35)
- 変更ファイル: `src/shared/types.ts`, `src/detection/advisory.ts`, `src/background/service-worker.ts`, `src/popup/render.ts`, `src/popup/popup.ts`, `src/popup/popup.css`, `src/dashboard/render.ts`, `src/dashboard/dashboard.css`, `src/export/csv.ts`, `src/export/markdown.ts`, `tests/advisory.test.ts`, `tests/service-worker.test.ts`, `tests/export.test.ts`, `tests/ui-escaping.test.ts`
- 判断したこと:
  - `SecurityAdvisory` 型および `advisory.ts` の照合結果に `fixStatus` (`fixed | partial | none | unknown`)、`kev` (`boolean`)、`kevDateAdded` (`string | null`)、4 段階の `severity` (`critical | high | medium | low`) を追加した。過去の保存済み履歴（大文字の重大度や `fixStatus` 未定義データ）との互換性を保つため、新規フィールドは任意（`?`）とし、`getEffectiveFixStatus` でフォールバック判定を行うようにした。
  - `formatAdvisoryRecommendation` と `resolveRecommendedVersion` を `fixStatus` ごとに分岐し、「公式の修正版はありません」は `fixStatus: 'none'` のときのみ出力し、`unknown` のときは「修正版の情報が DB にありません。ベンダーの情報を確認してください」、`partial` のときは「一部の系列には修正版がありません」を案内するようにした。
  - `service-worker.ts` の CVE 指摘生成（`SEC-CVE-*`）で重大度を 2 値に丸めず、ヒットした脆弱性の最大重大度（4 段階）を採用し、`kev: true` を含む場合は `critical` に引き上げるとともに、`observed` と `description` の双方に「悪用確認済み（CISA KEV）」の注記を含めるようにした。あわせて `SecuritySeverity` に `'critical'`、`securityFindings` に `critical?: number` を追加した。
  - 参照リンク生成（`advisory.ts` および `markdown.ts`）では、CVE ID がある場合は NVD リンク、GHSA のみの場合は `https://github.com/advisories/<GHSA>` を使用し、NVD に GHSA ID を結合した無効な URL を生成しないようにした。
  - Popup・Dashboard・エクスポート 3 形式（JSON / CSV / Markdown）すべてに `fixStatus`、`kev`（「悪用確認済み（CISA KEV）」）、4 段階重大度を表示・出力し、UI 描画時にはすべて `escapeHtml()` を通すようにした。
- 未解決: なし

## T04 「収録 DB 上は該当なし」と収録範囲の表示、多件数の表示  (2026-11-03 14:46)
- 変更ファイル: `scripts/advisories/build-db.mjs`, `src/shared/types.ts`, `src/security/version-matcher.ts`, `src/detection/advisory.ts`, `src/detection/engine.ts`, `src/popup/render.ts`, `src/dashboard/render.ts`, `src/export/json.ts`, `src/export/csv.ts`, `src/export/markdown.ts`, `tests/fixtures/advisory-db.fixture.json`, `tests/advisory-pipeline.test.mjs`, `tests/advisory.test.ts`, `tests/export.test.ts`, `tests/ui-escaping.test.ts`
- 判断したこと:
  - `scripts/advisories/build-db.mjs` で schemaVersion 2.2 を維持したまま `coverage.byProduct` に各製品の `{ count, sources }`（`curated`, `OSV`, `NVD`）を書き出すようにした。`coverage.byProduct` が未定義の古い DB やテストデータでも動作するよう、`advisory.ts` の `getProductCoverageInfo` で `libraries[key].versions` から収録件数と取得元をフォールバック計算する構成にした。
  - 過去に保存された履歴データ（v1.6.x 形式）でも UI 描画やエクスポート時に収録範囲・ステータスラベルが正しく表示されるよう、`DetectedTechnology` の新規フィールド（`productAdvisoryCount`, `productSources`, `advisoryDataVersion`, `upstreamAdvisoriesCount`, `advisoryStatusLabel`）はすべて任意（`?`）とし、`resolveTechAdvisoryDisplayInfo` で現行 DB から補完できるようにした。
  - 該当 0 件の表示を「収録 DB 上は該当なし」に変更し、収録件数・取得元（`curated / OSV / NVD`）・`dataVersion` を併記した。収録件数が 0 件の技術（DB 未登録の Tailwind CSS やエントリ 0 件の製品）は「この技術の脆弱性は収録していません」と表示するようにした。
  - 該当が 6 件以上の場合は `sortAdvisoriesByPriority`（KEV → 重大度 4 段階 → CVSS スコア降順）でソートした上で上位 5 件を表示し、残りを `<details class="advisory-more">`（「ほか N 件を表示」）で折りたたむようにした。折りたたみ内の要素にも `.advisory-card` クラスを付与し、推奨修正バージョンは折りたたみ前の全件から算出する。
  - ディストリビューションパッケージ版（`2.4.52-1ubuntu4` のようなハイフン表記に加え、`2.4.41 (Ubuntu)` や `Apache/2.4.41 (Ubuntu)` のような括弧表記）を `isLinuxPackageVersion` で検出し、`Needs Review` を維持したまま上流バージョンとして照合した場合の該当件数を `countUpstreamAdvisories` で算出し、「参考: 上流版では N 件該当」を添えるようにした。固定 DB（Apache 収録 3 件のうち `< 2.4.52` が 1 件、残りは `>= 2.4.49`）における `2.4.41 (Ubuntu)` の上流版該当件数は 1 件であることをテストで確認した。
- 未解決: なし

## T14 判断の反映  (2026-11-03 15:14)
- 変更ファイル: `data/advisories/catalog.json`, `data/advisories/curated.json`, `scripts/advisories/lib/eol.mjs`, `scripts/validate-advisories.mjs`, `scripts/verify-advisories-nvd.mjs`, `src/shared/types.ts`, `src/detection/advisory.ts`, `src/popup/render.ts`, `src/popup/popup.ts`, `src/dashboard/render.ts`, `src/export/csv.ts`, `src/export/markdown.ts`, `tests/fixtures/advisory-db.fixture.json`, `tests/advisory-pipeline.test.mjs`, `tests/advisory.test.ts`, `tests/version-check.test.ts`, `tests/export.test.ts`, `tests/ui-escaping.test.ts`
- 判断したこと:
  - D1（React 18 の表示と `cycleOverrides`）: `data/advisories/catalog.json` の `products.react.eol` に `cycleOverrides["18"]`（`status`, `label`, `note`）を追加し、`scripts/advisories/lib/eol.mjs` の `normalizeEol` で上書きを適用するようにした。また、`scripts/validate-advisories.mjs` で EOL エントリの `label`（120 文字以内）および `note`（300 文字以内）に HTML 特殊文字（`UNSAFE_TEXT`）が含まれないことを検証するようにした。
  - `src/shared/types.ts` の `EolInfo` および `src/detection/advisory.ts` の `LibraryEolEntry` に任意の `label` と `note` を追加し、`buildEolResult` で `entry.note` を推奨文（`recommendation`）に反映するとともに、Popup・Dashboard・CSV・Markdown エクスポートの各出力で `label`（`status` の具体的な説明）と `note` を表示・出力し、UI 描画時には必ず `escapeHtml()` を通すようにした。
  - D2（Bootstrap CVE-2019-8331 の範囲修正）: `data/advisories/curated.json` の `bootstrap` における `CVE-2019-8331` の `range` を `"< 3.4.1 || >= 4.0.0, < 4.3.1"` に修正して判断理由と参照先を `notes` に明記し、`scripts/verify-advisories-nvd.mjs` の `KNOWN_DEVIATIONS` に登録した。
  - D5（Angular 暫定対応 7 件の撤去）: T01 のプレリリース・ワイルドカード比較対応により OSV 由来の範囲式がそのまま評価可能になったため、`data/advisories/curated.json` の `angular.advisories` から暫定対応 7 件を撤去して空配列 `[]` とし、`scripts/verify-advisories-nvd.mjs` の `KNOWN_DEVIATIONS` からも該当 7 件を削除した。あわせてテスト用固定 DB（`tests/fixtures/advisory-db.fixture.json`）も D1・D2・D5 の内容に合わせて更新した。
- 未解決: なし
