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

## T07 Cookie の用途分類と一般 Cookie のチェック  (2026-11-07 14:29)
- 変更ファイル: `src/shared/types.ts`, `src/security/cookies.ts`, `src/storage/history.ts`, `src/export/markdown.ts`, `src/export/csv.ts`, `src/dashboard/render.ts`, `src/popup/render.ts`, `tests/cookies.test.ts`, `tests/dashboard-history.test.ts`
- 判断したこと:
  - **一般 Cookie のチェックの独立化と観測値への Cookie 名出力（指摘 B・N7）**: `src/security/cookies.ts` の `SEC-COOKIE-SECURE-GENERAL` から認証系の指摘が 0 件のときだけ出力する条件を撤廃し、認証系の FAIL（`SEC-COOKIE-HTTPONLY`・`SEC-COOKIE-SECURE`）と独立に出力するようにした。また観測値（`observed`）に対象の Cookie 名を最大 3 件出力し、3 件を超える場合は `他 ○ 件` と付記するようにした（あわせて `SEC-COOKIE-SECURE-CSRF` の観測値にも対象の Cookie 名を出力するようにした）。
  - **用途カテゴリの追加と履歴・エクスポート対応**: `CookieCategory` に `advertising`（広告・マーケティング）と `consent`（同意管理）を追加し、`SEC-COOKIE-SECURE-GENERAL` のチェック対象に含めた。`formatCookieCategory` と `normalizeCookieCategory` を公開関数化し、ダッシュボード（`renderCookiesTableHtml`）・ポップアップ（`renderCookieModalHtml`）・Markdown / CSV / JSON エクスポート・履歴読み込み（`sanitizeReportUrls`）で新用途の表示と出力に対応させるとともに、v1.7.0 以前の履歴や未知の用途値は既定値 `'general'`（一般・未分類）として安全に扱うようにした。
  - **名前の対応表の拡充と優先順位（指摘 A・L・N8）**: `KNOWN_COOKIES`（完全一致）および `KNOWN_COOKIE_PREFIXES`（プレフィックス一致）を拡充し、計測（`ai_session`, `ai_user`, `__utma`, `__utmb`, `__utmc`, `__utmt`, `__utmz`, `_mkto_trk`, `kndctr_*`）、広告（`_gcl_*`, `_fbp`, `_twpid`, `_twsid`）、同意管理（`OptanonConsent`, `OptanonAlertBoxClosed`, `zaraz-consent`, `CookieConsent`）、CSRF（`__RequestVerificationToken`, `anti_forgery*`, `antiforgery*`, `mw-wp-form-token`）、認証（`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `ASPSESSIONID*`, `_gh_sess`）をパターン判定より優先するようにした。さらにパターン判定でも、`token` を含んでも `verification` や `forgery`（または `csrf` / `xsrf`）を含む名前は CSRF とし、`ai_session` 等の計測用 Cookie に含まれる `session` が認証用と判定されないようにした。
  - **HTTP ページでの Cookie PASS 観測値の書き分け**: HTTP のページ（`isHttps === false`）では Secure 属性を付与できないため、`SEC-COOKIE-00`（PASS）の観測値を `${processedCookies.length} 件のCookieを検査（HTTP のため Secure は評価対象外）` と書き分けるようにした（HTTPS ページでは従来どおり `${processedCookies.length} 件のCookieを検査（全属性が適切）`）。
  - **既存テストの期待値の変更（全 1 件）**:
    1. `tests/cookies.test.ts` の「Cookie名に基づいて正しいカテゴリに分類されること」において、`classifyCookie('_fbp')` の期待値を `'analytics'` から `'advertising'` に変更した（理由: T07 の仕様「用途の追加: `advertising`（広告）… 名前の対応表を増やす: 広告: `_gcl_*`、`_fbp`、`_twpid`、`_twsid`」に従い、`_fbp` の分類を `analytics` から `advertising` に変更したため）。
- 未解決: なし

## T08 サーバー・基盤・言語の検出  (2026-11-07 15:55)
- 変更ファイル: `src/shared/types.ts`, `src/detection/rules/server.json`, `src/detection/rules/backend.json`, `src/detection/rules/language.json`, `src/detection/rules/services.json`, `src/detection/engine.ts`, `src/detection/advisory.ts`, `src/security/headers.ts`, `src/security/domain-analyzer.ts`, `src/security/version-matcher.ts`, `src/storage/exceptions.ts`, `src/dashboard/render.ts`, `src/popup/render.ts`, `src/popup/popup.ts`, `src/export/markdown.ts`, `docs/DETECTION_SPECIFICATION.md`, `README.md`, `tests/detection.test.ts`, `tests/security.test.ts`, `tests/domain-analyzer.test.ts`, `tests/advisory.test.ts`, `tests/spec-integrity.test.ts`
- 判断したこと:
  - **ディストリ版（指摘 N6）**: `src/detection/engine.ts` において `detectDistroHint` の呼び出しを `Server` と `X-Powered-By` ヘッダーのみに限定した。パッケージ版の接尾辞判定は、抽出されたバージョンの直後に続く文字列（`afterVer`）のみを対象とし、バージョンが抽出できなかったときのヘッダー全体のフォールバック走査を廃止した。また Fedora の `fc` は `\.fc\d{2}\b` のときのみ一致させるようにした（あわせて `src/security/version-matcher.ts` の `isLinuxPackageVersion` でも `fc` を `\.fc\d{2}\b` に限定）。これにより `x-vercel-id: hnd1::29cw8-1793972072729-626cb73fc75c` を含む応答で `distroHint` が付かず、`Apache/2.4.41 (Ubuntu)`・`nginx/1.10.3 (Ubuntu)`・`Apache/2.4.6 (CentOS)`・`PHP/8.1.2-1ubuntu2.14` は従来どおり動作する。
  - **Tomcat（指摘 N9）**: `src/detection/rules/server.json` に `tomcat`（`Tomcat`, `category: 'web-server'`）を追加し、`Server: Apache-Coyote/*` および `Server: Apache Tomcat*` から検出し、`implies` で `Java`（`runtime-dependency`, `runtimeStatus: 'unknown'`, `confidenceFactor: 0.95`）を推論するようにした。`Apache-Coyote/1.1` の `1.1` は HTTP/1.1 コネクタのプロトコル版であるため Tomcat のバージョンとしては抽出せず、`Apache Tomcat/<version>` のみバージョンを抽出する設計とした。また `apache` ルールの正規表現を `Apache(?![-\w]|\s+(?:Tomcat|Coyote))(?:/([0-9.]+))?` に更新し、`Apache-Coyote/*` や `Apache Tomcat*` から Apache httpd を誤検出しないようにした。
  - **旧 ASP（Classic ASP）**: `src/detection/rules/backend.json` に `classic-asp`（`Classic ASP`, `category: 'framework'`）を追加した。`src/detection/engine.ts` において、`ASPSESSIONID*` の Cookie が存在し、`ASP.NET_SessionId` Cookie も `X-AspNet-Version` ヘッダーも存在しない場合は `Classic ASP` とし、`X-Powered-By: ASP.NET` があっても `ASP.NET` を検出しないようにした（スナップショット `testasp.vulnweb.com.json` で `Classic ASP` になり `ASP.NET` が出ないことを確認）。
  - **ASP.NET（指摘 D）**:
    1. `X-AspNet-Version` の値を CLR の版として扱い、`formatAspNetClrVersion()` で `.NET Framework 4.x（CLR 4.0.30319）` や `.NET Framework 2.0〜3.5（CLR 2.0.50727）` の表示形式に変換するようにした（UI・Markdown のバージョン表示では、先頭が数字のときだけ `v` を付け、`.NET Framework ...` には `v` を付けないようにした）。
    2. `src/security/headers.ts` に `X-AspNet-Version` の露出チェック（`SEC-DISC-03`, `category: 'information-disclosure'`, `name: 'バックエンド技術情報露出 (X-AspNet-Version)'`, `status: 'warning'`, `severity: 'low'`、`X-Powered-By` と同じ扱い）を追加し、`SECURITY_HEADER_NAMES` と `src/storage/exceptions.ts` の `KNOWN_SECURITY_CHECK_SPECS` にも登録した。
    3. `src/detection/advisory.ts` の `matchOfflineAdvisories()` で ASP.NET の CLR 2.0 系（`2.0.50727` / `.NET Framework 2.0〜3.5（CLR 2.0.50727）`）を EOL（`status: 'EOL'`）として扱うようにした。なお、`advisory-db.json` の不変条件（`catalog.json` の全製品は CVE 1 件以上を持つ必要がある）を維持するため、CLR バージョンの EOL 判定は `advisory.ts` 内で直接行った。
    4. **【完了報告書向け控え: CLR 2.0 系 EOL の根拠 URL・日付】**:
       - 根拠 URL: `https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework` （Microsoft Lifecycle Policy — Microsoft .NET Framework）
       - 根拠日付: `.NET Framework 2.0 / 3.0` は **2011-07-12** サポート終了、`.NET Framework 3.5 SP1` 以外の 2.0〜3.5 系（特に ASP.NET 2.0 / Windows Server 2003・2008 世代の標準ランタイム構成）はメインストリームサポートが **2011-07-12**、Windows Vista / Server 2008 ベースの延長サポートが **2016-04-12**（`.NET Framework 4 / 4.5 / 4.5.1` のサポート終了日も **2016-01-12**）であり、本ツールでは `eolDate: '2016-04-12'` として記録した（CLR 4.0 `4.0.30319` はサポート中の `.NET Framework 4.8 / 4.8.1` と同一 CLR 番号のため断定せず `Unknown` とした）。
  - **カテゴリと状態（指摘 4）**: `TechnologyCategory` に `'framework'` を追加し、`Spring Security` と `ASP.NET`（および `Classic ASP`）を `programming-language` から `framework`（UI 表示: `フレームワーク`）に移した。また `src/detection/engine.ts` で直接検出時の `runtimeStatus` を `level === 'high' ? 'confirmed' : 'possible'` とし、確信度が `medium` 以下のときは「稼働確認済（`confirmed`）」にしないようにした。さらに `Spring Security` のルールに `SESSION` Cookie（Spring Session の既定名、weight 45）を追加し、単独では閾値（50）未満で誤検出せず、`_csrf`（weight 60）と組み合わさったときに確信度が上がる（60% → 69%）ようにした。
  - **Azure（指摘 G・A）**: `src/detection/rules/services.json` に `azure-app-gateway`（`Azure Application Gateway`, `category: 'hosting-cloud'`, Cookie `ApplicationGatewayAffinity*`）と `application-insights`（`Application Insights`, `category: 'analytics-tracking'`, Cookie `ai_session`・`ai_user` およびスクリプト URL `*.vo.msecnd.net`・`js.monitor.azure.com`）を追加した。あわせて `src/security/domain-analyzer.ts` の `inferServiceCategory()` で `*.vo.msecnd.net` と `js.monitor.azure.com` を `'analytics'` に分類した。
  - **既存テストの期待値の変更（全 1 件）**:
    1. `tests/spec-integrity.test.ts` の「ルール定義と仕様書カタログの登録技術数が完全に一致すること」において、登録技術数の期待値を `70` から `74` に変更した（理由: T08 の仕様に従い `Tomcat`、`Classic ASP`、`Azure Application Gateway`、`Application Insights` の 4 技術を追加し、`ASP.NET` を `language.json` から `backend.json` へ移動して合計 74 技術になったため）。
- 未解決: なし
