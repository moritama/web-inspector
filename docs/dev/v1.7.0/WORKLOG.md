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

## T05 NVD 自動取り込みの有効化、版を 1.7.0 に  (2026-11-03 17:29)
- 変更ファイル: `scripts/advisories/build-db.mjs`, `data/advisories/catalog.json`, `public/manifest.json`, `package.json`, `package-lock.json`, `src/detection/rules/index.ts`, `src/background/service-worker.ts`, `src/popup/popup.ts`, `src/dashboard/dashboard.ts`, `popup.html`, `dashboard.html`, `src/popup/popup.html`, `src/dashboard/dashboard.html`, `README.md`, `tests/advisory-db-invariants.test.ts`, `tests/advisory-pipeline.test.mjs`
- 判断したこと:
  - `scripts/advisories/build-db.mjs` の `MIN_EXTENSION_VERSION` を `'1.7.0'` に引き上げ、保守手順書 §1.2 および整合性テストの対象箇所（`public/manifest.json`, `package.json`, `package-lock.json`, `src/detection/rules/index.ts`, `src/background/service-worker.ts`, `src/popup/popup.ts`, `src/dashboard/dashboard.ts`, `popup.html`, `dashboard.html`, `src/popup/popup.html`, `src/dashboard/dashboard.html`, `README.md`）のバージョン表記をすべて `1.7.0`（HTML は `v1.7.0`）に統一した。
  - `data/advisories/catalog.json` において NVD 対象の 5 製品（`wordpress`, `php`, `nginx`, `apache`, `nodejs`）の `nvd.autoIngest` をすべて `true` に変更した（`data/advisories/curated.json` は指示どおり変更しない）。
  - `tests/advisory-db-invariants.test.ts` および `tests/advisory-pipeline.test.mjs` に T05 の検証を追加し、`minExtensionVersion` が `'1.7.0'` であること、未改変の本物の DB では総収録件数が 350 件以上（400 件前後）であること、Apache `2.4.52` を照合すると `CVE-2023-25690` が該当し `Apache/2.4.41 (Ubuntu)` は `Needs Review` のままであることを確認できるようにした（エントリ半減テスト `C04c` 時にも落ちないよう `versions.length === coverage.byProduct.apache.count` で未改変判定を併用）。
- 未解決: なし

## T06 CSP を積集合で評価  (2026-11-03 17:54)
- 変更ファイル: `src/security/csp-parser.ts`, `src/security/headers.ts`, `src/background/service-worker.ts`, `src/content/content-script.ts`, `src/shared/types.ts`, `tests/csp-parser.test.ts`, `tests/review-v1.6.5-acceptance.test.ts`
- 判断したこと:
  - `src/security/csp-parser.ts` に `parseCSPHeaderValues` を追加し、HTTP レスポンスヘッダーの配列要素ごと、およびカンマ（`,`）区切りごとに別々の `CSPPolicy` オブジェクトとして分割・解析するようにした。`src/security/headers.ts`（`checkHttpHeaders`）と `src/background/service-worker.ts`（`executeInspection`）の双方でこの関数を用いることで、複数ヘッダー行とカンマ区切り 1 行のどちらで送信されても同一の判定になるよう統一した。
  - 複数の強制ポリシー（`mode === 'enforce'`）の評価を能力（インライン実行、eval、任意ホストからのスクリプト、`object-src`、`base-uri`、`frame-ancestors`）単位の積集合（AND）に変更した。各能力についてすべての強制ポリシーが許容している場合のみ指摘を残し、1 つでも遮断している強制ポリシーがあれば防御済みとして扱うようにした。
  - スクリプトの任意ホスト許可（`CSP-SCRIPT-WILDCARD`）の対象を拡大し、`*`、`https:`、`http:`（および `https://*` 等）を `high`、サブドメインワイルドカード（`*.example.com` 等）を `medium` として検出するようにした。また `nonce-*` / `sha256|384|512-*` と `'strict-dynamic'` がある場合は、CSP Level 3 仕様に従いホスト許可と `'unsafe-inline'` が無視されることを反映した。
  - `severity: 'info'` の注記（`CSP-SCRIPT-STRICT-DYNAMIC-NOTE` や nonce/hash 共存時の `'unsafe-inline'` 実効的無効化注記）は `SEC-CSP-03` の指摘件数（`actionableEnforceIssues`）に含めず、他に警告事項がなければ `SEC-CSP-00`（`status: 'pass'`）になるようにした。
  - `src/content/content-script.ts` で `<meta http-equiv="Content-Security-Policy-Report-Only">` を `metaCspReportOnly`（`DomSignals` の任意フィールド）として分離収集し、`analyzeCSPPolicies` では meta の Report-Only をポリシー評価から外した上で「無効な指定」として `info` の注記（`SEC-CSP-META-RO`, `status: 'info'`, `severity: 'info'`）を 1 件出力するようにした。meta の Report-Only のみがあるページでは CSP は「未設定」（`SEC-CSP-01`）扱いとなり、あわせて `info` 注記が 1 件出力される。
  - 既存の `tests/csp-parser.test.ts` のテストは期待値を 1 件も変更せずにそのまま維持し、DOM 抽出を含む新規テストを追加するとともにファイル先頭に `// @vitest-environment happy-dom` を付与した。
- 未解決: なし

## T07 ヘッダー値の検証、混在コンテンツの対象拡大  (2026-11-03 19:20)
- 変更ファイル: `src/security/headers.ts`, `src/background/service-worker.ts`, `src/security/cookies.ts`, `src/security/https.ts`, `src/content/content-script.ts`, `src/shared/types.ts`, `docs/DETECTION_SPECIFICATION.md`, `tests/review-v1.6.5-acceptance.test.ts`, `tests/security.test.ts`, `tests/content-script.test.ts`, `tests/cookies.test.ts`
- 判断したこと:
  - `src/security/headers.ts` に `isValidXFrameOptions` を追加し、`X-Frame-Options` が `DENY` または `SAMEORIGIN` 以外（`ALLOWALL`、`ALLOW-FROM`、不正値）の場合は `pass` にせず `SEC-XFO-02`（`status: 'warning'`, `severity: 'medium'`）とした。ただしレスポンスヘッダーの強制 CSP に `frame-ancestors` がある場合はブラウザ仕様どおりそちらを優先して `SEC-XFO-00`（`pass`）とし、`analyzeCSPPolicies` に渡す `hasXfo` フラグも `isValidXFrameOptions` で判定するように `headers.ts` と `service-worker.ts` を統一した。
  - HSTS について、`max-age=0`（明示的な無効化）または `max-age` 未指定は `SEC-HSTS-02` の `severity: 'medium'`、`max-age` が 1 年（31536000 秒）未満の場合は `severity: 'low'`、1 年以上の場合は `SEC-HSTS-00`（`pass`）とした。
  - `Referrer-Policy` について、カンマ区切りのフォールバック指定時はブラウザ仕様どおり最後の認識可能なトークンを有効値として評価し、`unsafe-url` および認識不能な無効値は `SEC-REF-02`（`status: 'warning'`, `severity: 'low'`）、`no-referrer-when-downgrade` は `SEC-REF-03`（`status: 'info'`, `severity: 'info'`）とした。
  - CORS について、`Access-Control-Allow-Origin: *` と `Access-Control-Allow-Credentials: true` の組み合わせはブラウザが拒否するため、`SEC-CORS-01` の重大度を `high`（`fail`）から設定ミス指摘の `info`（`status: 'info'`, `severity: 'info'`）に変更した。
  - D7 に従い、ブラウザがそもそも保存しない Cookie を対象にしたチェック（Cookie プレフィックス違反 `SEC-COOKIE-PREFIX`、`SameSite=None` で `Secure` なし、`Partitioned` で `Secure` なし）を `src/security/cookies.ts` から削除し、`docs/DETECTION_SPECIFICATION.md` の図表文言からもプレフィックス表記を外した。ファイル自体の削除は不要であった。
  - 混在コンテンツ（SPEC-15）について、`src/content/content-script.ts` の収集対象に `img[srcset]`、`video[src]`、`audio[src]`、`source[src]` / `source[srcset]`、`object[data]`、`embed[src]`、`form[action]` を追加した。`src/security/https.ts` ではパッシブ混在（`image`, `video`, `audio`, `other`）をブラウザの HTTPS 自動昇格を考慮して `severity: 'low'` とし、アクティブ混在（`script`, `stylesheet`, `iframe`, `object`, `embed`, `fetch`）および平文 HTTP の `form[action]`（`form`）を `severity: 'high'` として説明文にも反映した。
- 未解決: なし
