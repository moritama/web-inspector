# v1.7.1 作業記録

各タスクの完了時に、次の形式で追記してください。完了報告書の材料になります。このファイルはコミットされるので、作業者のユーザー名・ローカルパス・ツールの製品名は書かないでください。

```
## T00 <タスク名>  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <指示書に書かれていなかったことをどう決めたか>
- 未解決: <あれば>
```

---

## T01 ステータス表示と件数の整合  (2026-11-07 03:03)
- 変更ファイル: `src/shared/security-status.ts`, `src/background/service-worker.ts`, `src/security/headers.ts`, `src/export/markdown.ts`, `src/popup/render.ts`, `src/popup/popup.ts`, `src/dashboard/render.ts`, `tests/security.test.ts`, `tests/service-worker.test.ts`
- 判断したこと:
  - 「要確認（`requiresAttentionCount`）」「重大度の内訳（`securityFindings` の CRITICAL〜LOW）」「INFO 行」「表・UIのステータス表示」の判定ロジックを `src/shared/security-status.ts` に一元化した。CRITICAL〜LOW は要確認対象（`status` が `warning` または `fail` かつ許容・除外設定されていない項目）のみを集計し、INFO は `status` が `pass` または `info` の件数を集計することで、CRITICAL〜LOW の合計が常に `requiresAttentionCount` と一致するようにした。
  - `Referrer-Policy` 未設定時（`SEC-REF-01`）はブラウザ既定値（`strict-origin-when-cross-origin`）で安全であるため、`status: 'info'`, `severity: 'info'` に統一した。
  - `X-Frame-Options` の診断項目名（`name`）を PASS・WARN・`frame-ancestors` 判定のすべてで `'X-Frame-Options'` に統一し、`frame-ancestors` で判定した場合は `observed` に `'CSP frame-ancestors により保護'` を含めて区別できるようにした。
  - Markdown 出力（`src/export/markdown.ts`）およびポップアップ行描画（`src/popup/render.ts`）で `observed` 文字列を固定文字数（60文字・42文字）で切り詰めていた処理が、CISA KEV 該当時の `SEC-CVE-*` の観測値（61文字）の末尾閉じ括弧 `)` を欠落させていたため、固定文字数での切り詰めを廃止して括弧の対応が崩れないようにした。
  - 既存テストの期待値の変更はなし。
- 未解決: なし

## T02 Markdown 出力の整理（ロードマップ、エスケープ、表現）  (2026-11-07 03:27)
- 変更ファイル: `src/export/markdown.ts`, `src/dashboard/dashboard.ts`, `tests/markdown.test.ts`
- 判断したこと:
  - 推奨対応ロードマップ（セクション 13、E3・指摘 1）から固定文を撤廃し、`isRequiresAttention(c)` が true となる要確認の指摘のみから動的に組み立てるようにした。重大度に応じて「至急対応 (CRITICAL / HIGH)」「計画的対応 (MEDIUM)」「継続的改善 (LOW)」に分類し、該当項目がある段のみを出力し、各行は「指摘名（`c.name`）: 推奨対応（`c.recommendation` の 1 文目）」とした。要確認が 0 件の場合は「対応が必要な項目はありません。」を出力するようにした。
  - コードスパンおよび表セルのエスケープ（指摘 7）について、`formatMarkdownCodeSpan` と `escapeMarkdownTableCell` を分離した。コードスパン内では `escapeMarkdown` を使わず、値にバッククォートが含まれる場合は連続バッククォートの最大長+1個のバッククォートで囲むようにし、表セル内ではパイプ文字 `|` のみを `\|` にエスケープするようにした。
  - 前回レポートとの比較を行っていない場合（`!diff`）、セクション 11「差分発生原因の推定分析」も「比較未実行のため対象外です（前回調査レポートとの比較は実行されていません）。」と出力するようにした（指摘 8）。
  - セクション 6「EOL・既知脆弱性情報」（指摘 6）について、(1) 注記の `Rev.2.1` を削除して概要と同じ書式（`YYYY-MM-DD`）の DB バージョンを表示（あわせて `src/dashboard/dashboard.ts` の画面表示文言からも `Rev.2.1` を除去）、(2) EOL 時の「最新LTS系列への移行」は LTS 系列を持つ技術（Node.js、Angular、Laravel 等）のみとし、Bootstrap 等は「サポート中のメジャーバージョンへの移行」に変更、(3) バージョン不明時は「評価不可（バージョン不明）」、収録対象外は「評価不可（収録対象外）」に変更、(4) 該当 CVE が 0 件で照合ステータス列と文言が重複する場合は該当 CVE/GHSA 列を `-` に統一した。
  - セクション 7「Cookie属性診断」（指摘 5）に、親ドメインをスコープとする Cookie は同一ドメイン配下の別サイト・別ページで発行された可能性があり「このページが設定したとは限らない」旨の注記を 1 行追加した。
  - 既存テストの期待値の変更（全 1 件）: `tests/markdown.test.ts` の「Cookie値（Value）や機密トークンがレポートに含まれないこと」において、Cookie 名 `SESSION_ID` の出力期待値を `SESSION\_ID` から `` `SESSION_ID` `` に変更した（理由: 指摘 7 により、コードスパン内では `escapeMarkdown` を使わず `_` 等にバックスラッシュを付けない仕様に変更したため）。
- 未解決: なし

## T03 整合性チェッカーと回帰用フィクスチャ、collect-reports.mjs --snapshot  (2026-11-07 04:51)
- 変更ファイル: `package.json`, `scripts/report-lint.mjs`, `scripts/collect-reports.mjs`, `test-server/server.mjs`, `tests/fixtures/.gitignore`, `tests/fixtures/reports/csp-frame-ancestors.json`, `tests/fixtures/reports/csp-frame-ancestors.md`, `tests/fixtures/reports/app-insights-cookies.json`, `tests/fixtures/reports/app-insights-cookies.md`, `tests/fixtures/reports/relative-urls-only.json`, `tests/fixtures/reports/relative-urls-only.md`, `tests/fixtures/reports/wordpress-legacy-ga.json`, `tests/fixtures/reports/wordpress-legacy-ga.md`, `tests/report-lint.test.ts`
- 判断したこと:
  - レポート（JSON と Markdown の組）を機械的に検査する `scripts/report-lint.mjs` と `npm run reports:lint` を実装した。検査項目 (1) R01〜(8) R08 のうち、後続タスクで有効化する (4) R04（根拠のホストと通信先の整合・非通信参照ホストの除外）と (8) R08（完全性が「完全」なら通信先 1 件以上）を `pending: true`（保留）として定義し、CLI 出力および `_summary.md` に保留件数と対象項目を表示するようにした。
  - `scripts/collect-reports.mjs` を拡張し、(a) レポート取得後に `lintReportPair` を実行して合否と違反詳細を `_summary.md` に出力する処理、(b) `--snapshot` オプション指定時に HTML（`page.content()`）、サニタイズ済みメイン文書レスポンスヘッダー（`Set-Cookie` の値や `Authorization` / `Cookie` ヘッダーを除去）、Resource Timing 一覧、値を除去した Cookie 属性一覧を `snapshots/` に保存する処理を追加した。
  - 合成データによる回帰用フィクスチャ 4 組（`csp-frame-ancestors`、`app-insights-cookies`、`relative-urls-only`、`wordpress-legacy-ga`、ホスト名はすべて `*.example.test`）を `tests/fixtures/reports/` に作成し、`generateMarkdownReport` の出力と完全一致するように整形した。あわせて対応する再現エンドポイント 4 件を `test-server/server.mjs` に追加した。ルート `.gitignore` の `reports/` パターンによって `tests/fixtures/reports/` が Git 追跡対象から除外されるのを防ぐため、`tests/fixtures/.gitignore` で `!reports/` を指定した。
  - `tests/report-lint.test.ts` を追加し、各検査項目 (1)〜(8) の違反検出、v1.7.0 修正前レポートで (1)(2)(3)(6) が不合格になり T01・T02 修正後レポートで合格すること、回帰用フィクスチャ全 4 件の合格、`collect-reports.mjs` の `--snapshot` 引数解析・ヘッダー/Cookie サニタイズ・サマリー出力を検証した。
  - 既存テストの期待値の変更はなし。
- 未解決: なし

## T05 通信先の作り直し（相対 URL 解決、Resource Timing、非通信 link の除外）  (2026-11-07 07:10)
- 変更ファイル: `src/shared/types.ts`, `src/content/content-script.ts`, `src/security/domain-analyzer.ts`, `src/background/service-worker.ts`, `src/export/markdown.ts`, `src/dashboard/render.ts`, `src/dashboard/dashboard.ts`, `PRIVACY_POLICY.md`, `scripts/report-lint.mjs`, `test-server/server.mjs`, `scripts/test-e2e-smoke.mjs`, `tests/fixtures/reports/app-insights-cookies.md`, `tests/fixtures/reports/csp-frame-ancestors.md`, `tests/fixtures/reports/relative-urls-only.md`, `tests/fixtures/reports/wordpress-legacy-ga.md`, `tests/content-script.test.ts`, `tests/domain-analyzer.test.ts`, `tests/markdown.test.ts`, `tests/report-lint.test.ts`
- 判断したこと:
  - 相対 URL の解決（指摘 F・N3）: Content Script（`src/content/content-script.ts`）で `script[src]` と `link[href]` および CSS 検査対象 URL を `document.baseURI`（またはフォールバックの `location.href`）基準の絶対 URL に解決するようにした。元の属性値も `rawScriptUrls`・`rawLinkUrls` に保持し、技術検出エンジンへの入力にも影響が出ないようにした。また `analyzeExternalConnections` でも第1引数の `pageUrl` を基準に相対パスを解決できるようにし、テスト等で直接相対パスが渡された場合も漏れなく集計されるようにした。
  - 実際に読み込まれたリソースの収集（E2 = A）: `extractDomSignals()` で `performance.getEntriesByType('resource')` から `name` と `initiatorType` を収集し（`resourceEntries`）、加えて DOM 上の読み込み対象要素（`script[src]`、対象 `link[href]`、`img[src]`、`iframe[src]`、`video`/`audio`/`source`/`embed`/`object`、ただし `noscript`/`template` 内は除外）の解決済み URL（`domResourceUrls`）で補完して重複を除いた一覧を `collectLoadedResourceUrls(pageUrl, domSignals)` で組み立てるようにした。メイン文書自体（`pageUrl`）も自ホストの 1 リソースとしてカウントすることで、サブリソースを持たない単一 HTML ページ（`http.badssl.com` 等）や相対 URL のみのページでも自ホストが必ず通信先に計上されるようにした。
  - 非通信 link および form 送信先の除外（指摘 F・N1）: DOM の `<link>` から通信先および `linkUrls` に入れる対象を `rel` トークンに `stylesheet`, `preload`, `modulepreload`, `icon`（`shortcut icon`・`apple-touch-icon` 等を含む）, `manifest` を持つもののみに限定した。`alternate`（`hreflang` 等）、`canonical`、`prev`/`next`、`dns-prefetch`、`preconnect`、および `<form action="...">` の送信先は通信先には入れず、`referenceOnlyUrls` に分離して保持するようにした（混在コンテンツの `form` 検査は従来どおり維持）。
  - サンプル URL のマスク: `analyzeExternalConnections` で `sampleUrls` に格納する URL に `stripUrlQueryAndFragment` を適用し、クエリ文字列（`?token=...` 等）やフラグメントがレポートの通信先サンプル URL に残らないようにした。
  - 見出しと説明文の明確化（指摘 N1）: Markdown レポート（`src/export/markdown.ts`）のセクション 9 見出しを `## 9. 外部通信先・サードパーティ分析（読み込まれたリソースの取得元 / eTLD+1）` に更新し、ページ本体と実際に読み込まれたサブリソースを集計対象とし `alternate` リンクや `form` の送信先など読み込みを伴わない参照は含めない旨の説明文を追加した。あわせてダッシュボードの外部通信先ビュー（`src/dashboard/render.ts`, `src/dashboard/dashboard.ts`）の見出し・説明文も同じ趣旨に更新した。
  - `PRIVACY_POLICY.md` の更新内容（差分要旨）: 第2章（英語・日本語の Content Scripts 項目）および第4章（`activeTab` / `scripting` の用途説明）に、調査実行時にオンデマンド注入された Content Script が DOM に加えて Performance Resource Timing API（`performance.getEntriesByType('resource')`）から読み込み済みサブリソースの URL と `initiatorType` を受動的に読み取りメモリ上で評価すること、およびレポートに記録する外部通信先のサンプル URL からもクエリ文字列とフラグメントを除去・マスクすることを追記した。
  - 整合性チェッカー（`scripts/report-lint.mjs`）の (4) R04 と (8) R08 の保留を解除（`pending: false, pendingUntil: null`）し、全 8 項目が既定で有効（保留 0 件）になるようにした。
  - 既存テストの期待値の変更（全 2 件）:
    1. `tests/report-lint.test.ts` の「既定設定では (4) R04 と (8) R08 が保留（pending）として定義されていること」を「T05 で (4) R04 と (8) R08 の保留が解除され、全 8 項目が既定で有効（保留 0 件）になっていること」に更新し、`getPendingChecks()` の期待値を `['R04', 'R08']` から `[]` に変更した（理由: T05 の受け入れ条件に従い R04 と R08 の保留を解除したため）。
    2. `tests/fixtures/reports/*.md`（`app-insights-cookies.md`, `csp-frame-ancestors.md`, `relative-urls-only.md`, `wordpress-legacy-ga.md` の 4 ファイル）のセクション 9 の見出しと冒頭説明文を更新した（理由: 指摘 N1 により `src/export/markdown.ts` のセクション 9 見出し・説明文を更新したことに伴い、`tests/report-lint.test.ts` の `generateMarkdownReport(report)` 一致検証を同期させるため）。
- 未解決: なし

## T06 完全性、DOM 検出漏れの調査、混在コンテンツの URL  (2026-11-07 08:01)
- 変更ファイル: `src/detection/rules/frontend.json`, `src/detection/rules/cms.json`, `src/content/dom-selectors.generated.ts`, `docs/DETECTION_SPECIFICATION.md`, `README.md`, `src/content/content-script.ts`, `src/shared/types.ts`, `src/shared/coverage.ts`, `src/background/service-worker.ts`, `src/export/markdown.ts`, `src/security/https.ts`, `test-server/server.mjs`, `tests/fixtures/dom-signal-fixtures.ts`, `tests/coverage.test.ts`, `tests/service-worker.test.ts`, `tests/security.test.ts`, `tests/content-script.test.ts`, `tests/detection.test.ts`
- 判断したこと:
  - **N2 の調査と対応（3 サイトのスナップショット調査とルール・探査の強化）**:
    - `test-server/server.mjs` に `tests/fixtures/snapshots/` の HTML とレスポンスヘッダーを配信する `/snapshots/<site>` エンドポイントを追加し、3 サイト（`angular.dev`, `angularjs.org`, `www.drupal.org`）のスナップショットを調査した。
    1. **`angular.dev`**: `tests/fixtures/snapshots/angular.dev.html`（293 行目）に `<adev-root ng-version="22.2.5+sha-d881689" _nghost-ng-c1178817259="" ng-server-context="ssg">` が存在していたが、`src/detection/rules/frontend.json` の `[ng-version]` の正規表現が `ng-version="([0-9.]+)"` だったため、ビルドメタデータ（`+sha-d881689`）付きの値に一致せず検出漏れとなっていた。`pattern` を `ng-version="([0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?)"`、`versionRegex` を `ng-version="([0-9]+(?:\.[0-9]+)*)"` に修正したことで、`angular.dev` スナップショットから Angular `22.2.5`（確信度 95）が検出されるようになった。さらに `ng-version` を出さない本番ビルド向けに `_nghost-*` / `_ngcontent-*`（`content-script.ts` の属性接頭辞探査にも追加）および `[ng-server-context]` を代替シグナル（weight 85）として追加した。
    2. **`angularjs.org`**: `tests/fixtures/snapshots/angularjs.org.json`（`statusCode: 404`）および `tests/fixtures/snapshots/angularjs.org.html`（全 104 行）を確認したところ、7 行目 `<title>Site Not Found</title>`、95 行目 `<h2>404</h2>`、96 行目 `<h1>Site Not Found</h1>`、99 行目 `Why am I seeing this? ... Refer to our <a href="https://firebase.google.com/docs/hosting/">hosting documentation</a>` という Firebase Hosting の既定 404 エラーページが返っており、HTML・ヘッダー・Resource Timing のいずれにも AngularJS の印やスクリプトは一切含まれていなかった。ルール側には代替シグナルとして `[data-ng-app]`、`[data-ng-controller]`、`[ng-model]`、`[data-ng-model]`、`[ng-bind]`、`[ng-repeat]`、`[ng-cloak]`、`.ng-scope`、`.ng-binding` を追加し、否定コントロール（`loading-spinner` や `ng-loading-indicator` で誤検出しないこと）のテストを追加した。
    3. **`www.drupal.org`**: `tests/fixtures/snapshots/www.drupal.org.html`（全 1 行）を確認したところ、`<title>Client Challenge</title>`、`<script src="/_fs-ch-1T1wmsGaOgGaSxcX/script.js?reload=true"></script>`、`<img id="fastlyLogo" alt="Fastly Logo" src="data:image/svg+xml;base64,...">`、`<p id="captchaTitle">Enter the characters seen in the image below:</p>` という Fastly の Bot / CAPTCHA チャレンジ（Client Challenge）インタースティシャルページが返っており、HTML・ヘッダー・Resource Timing のいずれにも Drupal の印は一切含まれていなかった。ルールおよび Content Script 側には、通常の Drupal ページで観測される `x-drupal-dynamic-cache` ヘッダー、`data-drupal-*` 属性接頭辞探査（`[data-drupal-selector]`, `[data-drupal-messages]`, `[data-drupal-link-system-path]`, `script[data-drupal-selector='drupal-settings-json']`）、`/core/misc/drupal.js` 等の固有スクリプトパス、`/core/themes/` 等の固有リンクパスを代替シグナルとして追加し、一般的な `/core/app.js` 等で誤検出しない否定コントロールのテストを追加した。
  - **完全性（Coverage）の改善**:
    - `countDomItems(domSignals)` を新設し、`domItemCount` を `metaTags` と `scriptUrls` だけでなく、収集した DOM の印（`domMarkers`）、スタイルシート（`linkUrls` の `stylesheet` と `cssAssets` の大きい方）、クラス名（`htmlSnippets`）の件数も含めて合算するようにした。
    - `extractDomSignals()` の各収集ステップを個別の `try/catch`（`runStep`）で保護し、途中で例外が発生しても残りのステップの収集を継続しつつ `collectionPartial: true` と `collectionErrors` を記録するようにした。また `fetchDomSignals` でスクリプト注入やメッセージ通信が失敗した場合も `collectionPartial: true` とエラー理由を記録するようにした。
    - `assessInspectionCoverage()` において、(a) Content Script の収集が途中で失敗したとき（`domCollectionPartial: true`）、および (b) DOM にリソースの参照があるのに通信先が 0 件のとき（`hasDomResourceReferences && externalConnectionCount === 0`）に、完全性を「部分的（`partial`）」にし、`details.partialReasons`（および Markdown レポートのセクション 2 の「部分的となった理由」）に理由を出力するようにした。
  - **混在コンテンツ（指摘 I）の観測値への要素・URL 出力**:
    - `src/security/https.ts` の `checkHttpsAndMixedContent()` で、`SEC-MIXED-ACTIVE` と `SEC-MIXED-PASSIVE` の `observed` に `<件数>件 (<要素>: <マスク済みURL>, ...)` の形式で対象の要素（`script`, `form[action]`, `img`, `iframe`, `link`, `video`, `audio`, `object`, `embed`）と `stripUrlQueryAndFragment` でクエリ・フラグメントをマスクした URL を最大 3 件出力し、3 件を超える分は `（他 ○ 件）` と付記するようにした。
    - `badssl` の 3 サイト（`mixed.badssl.com`、`mixed-script.badssl.com`、`mixed-form.badssl.com`）のスナップショットで、混在コンテンツの観測値にそれぞれ `img: http://mixed.badssl.com/image.jpg`、`script: http://mixed-script.badssl.com/nonsecure.js`、`form[action]: http://http.badssl.com/resources/form-submitted.html` が出ることを単体テストで検証した。
  - 既存テストの期待値の変更はなし。
- 未解決:
  - N2 の 3 サイトのスナップショットのうち、`angular.dev` では Angular `22.2.5` が検出されるようになったが、`angularjs.org` のスナップショット（`tests/fixtures/snapshots/angularjs.org.html` 7 行目 `<title>Site Not Found</title>`、95〜99 行目 Firebase Hosting の 404 エラーページ）および `www.drupal.org` のスナップショット（`tests/fixtures/snapshots/www.drupal.org.html` 1 行目 `<title>Client Challenge</title>`、`<img id="fastlyLogo">`、`<p id="captchaTitle">` の Fastly CAPTCHA チャレンジページ）にはサイト側の応答自体に当該技術の印が含まれていないため、スナップショット単体からは検出できない（指示書の受け入れ条件に従い、根拠を明記して `partial`（一部完了）とする）。
