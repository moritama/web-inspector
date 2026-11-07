# v1.7.1 完了報告書

## 1. サマリー

- 作業期間: 2026-11-07 〜 2026-11-08
- ブランチ / 最終コミット: `feature/v1.7.1` / `b982d08`（起点はタグ `v1.7.0`）
- 結果: 完了 10 / 一部完了 1 / 未完了 0（夜間キットのタスク 11 件。T00・T04 は人の作業）
- 総合チェック（`node scripts/dev/check-v1.7.1.mjs`）: FAIL（24 PASS / 1 FAIL / 0 WARN。C08 は本報告書の作成で解消（スクリプトが再チェック）。WARN なし）
- 実施体制: 夜間（無人）モードで実施。コーディングは AI コーディングエージェント、DB の再生成・テスト・コミットは夜間スクリプトがサンドボックスの外で実行。
- 一言で: 実サイト検査で判明したレポートの不整合（要確認件数と重大度内訳の不一致、`info` 項目の WARN 表示、固定文の推奨対応ロードマップ、コードスパン内の不要なバックスラッシュ、status による診断項目名の変化）と判定の誤り（DOM 参照に依存していた外部通信先集計、一般 Cookie 検査の認証系依存と用途分類不足、CSP 指摘の過大な重大度と問題点非表示、ディストリ版の誤検出、Tomcat・Classic ASP・ASP.NET・Azure・WordPress コア版/プラグイン一覧・Bootstrap 6 と Tailwind・廃止済み GA タグ・CISA KEV の名指し・HSTS preload 条件・混在コンテンツの要素/URL 表示・調査完全性判定）を改修し、レポート整合性チェッカー（全 9 項目・保留 0 件）と回帰用フィクスチャを整備した。残るのは、取得時のスナップショット自体に当該技術の印が含まれていなかった 2 サイト（`angularjs.org` の 404 応答、`www.drupal.org` の Fastly チャレンジ応答）の実環境での確認（T06 一部完了）、および人間による E2E 実行・実サイトでのレポート取り直し・画面の目視確認・`PRIVACY_POLICY.md` の文言承認。

## 2. 実行環境

| 項目 | 値 |
| --- | --- |
| OS | macOS 27.2 |
| Node.js / npm | v24.13.0 / 11.6.2 |
| AI コーディングエージェント / モデル | AI コーディングエージェント CLI: 1.5.3 / model: 既定（未指定） |

## 3. タスク別結果

| ID | 指摘 | 結果 | コミット | 追加・変更したテスト | 期待値を変えた既存テスト | 備考 |
| --- | --- | --- | --- | --- | --- | --- |
| T01 | 2、9、E、H、N13 | 完了 | `aedee7e` | `tests/security.test.ts`, `tests/service-worker.test.ts` | なし | 要確認件数・重大度内訳・ステータス表示の一元化、Referrer-Policy 未設定の `info` 化、XFO 項目名統一、KEV 観測値の閉じ括弧欠落修正 |
| T02 | 1、5、6、7、8 | 完了 | `134f146` | `tests/markdown.test.ts` | `tests/markdown.test.ts`（1 件） | 推奨対応ロードマップの動的生成、コードスパン/表セルのエスケープ分離、未比較時の差分表現、EOL・脆弱性表の表現整理、親ドメイン Cookie 注記 |
| T03 | 全体 | 完了 | `85d1709` | `tests/report-lint.test.ts`, `tests/fixtures/reports/*.json`, `tests/fixtures/reports/*.md` | なし | 整合性チェッカー（R01〜R08、うち R04・R08 は T05 まで保留）と回帰用フィクスチャ 4 組、`collect-reports.mjs --snapshot` |
| T05 | F、N1、N3 | 完了 | `2cc4213` | `tests/content-script.test.ts`, `tests/domain-analyzer.test.ts`, `tests/markdown.test.ts`, `tests/report-lint.test.ts`, `tests/fixtures/reports/*.md` | `tests/report-lint.test.ts`（1 件）、`tests/fixtures/reports/*.md`（4 ファイル） | Resource Timing 主体＋`baseURI` 基準絶対 URL 解決への通信先刷新、非通信 link・form 除外、R04・R08 保留解除、`PRIVACY_POLICY.md` 更新（§8 参照） |
| T06 | N2、I | 一部完了 | `9e2eca5` | `tests/coverage.test.ts`, `tests/service-worker.test.ts`, `tests/security.test.ts`, `tests/content-script.test.ts`, `tests/detection.test.ts`, `tests/fixtures/dom-signal-fixtures.ts` | なし | 調査完全性改善・混在コンテンツ要素/URL 表示・`angular.dev` 検出修正は完了。`angularjs.org` と `www.drupal.org` はスナップショット応答に印が無く代替シグナル追加で対応（調査結果は §7・§8） |
| T07 | A、B、L、N7、N8 | 完了 | `cda19cf` | `tests/cookies.test.ts`, `tests/dashboard-history.test.ts` | `tests/cookies.test.ts`（1 件） | 一般 Cookie チェックの独立化、6 用途分類（`advertising`・`consent` 追加）、既知 Cookie 名対応表の拡充、HTTP ページの PASS 観測値書き分け |
| T08 | 4、D、G、N6、N9 | 完了 | `cc4e3ed` | `tests/detection.test.ts`, `tests/security.test.ts`, `tests/domain-analyzer.test.ts`, `tests/advisory.test.ts`, `tests/spec-integrity.test.ts` | `tests/spec-integrity.test.ts`（1 件） | ディストリ版判定の厳密化、Tomcat と Java 連動、Classic ASP 分離、ASP.NET CLR 版表示と露出指摘、`framework` 分類と確信度連動の稼働状態、Azure 系検出（CLR 2.0 の EOL 判定は T11 で `Unknown` に修正） |
| T09 | E、J、K、L、N5 | 完了 | `452968d` | `tests/detection.test.ts`, `tests/content-script.test.ts`, `tests/domain-analyzer.test.ts`, `tests/security.test.ts`, `tests/markdown.test.ts`, `tests/spec-integrity.test.ts`, `tests/fixtures/reports/wordpress-legacy-ga.*` | `tests/spec-integrity.test.ts`（1 件）、`tests/fixtures/reports/wordpress-legacy-ga.json`・`.md` | Bootstrap 6 と Tailwind の誤認防止、根拠の重複統合と代表 3 件表示、WordPress コア `ver` とプラグイン・テーマ一覧、GTM・Facebook SDK・廃止済み GA タグ `INFO`・reCAPTCHA 分類 |
| T10 | 3、N4 | 完了 | `8d78d1f` | `tests/csp-parser.test.ts`, `tests/markdown.test.ts`, `tests/report-lint.test.ts`, `tests/fixtures/reports/*.md` | `tests/csp-parser.test.ts`（2 件）、`tests/report-lint.test.ts`（2 件）、`tests/fixtures/reports/csp-frame-ancestors.md`・`relative-urls-only.md` | CSP 最大重大度 `MEDIUM` 上限、ヘッダー＋`meta` 積集合評価、観測値要約とポリシー別問題点表、XFO と `frame-ancestors` の優先関係注記、チェッカー R09 追加 |
| T11 | C、E、N11、N12 | 完了 | `ae65597` | `tests/advisory.test.ts`, `tests/detection.test.ts`, `tests/exceptions.test.ts`, `tests/export.test.ts`, `tests/markdown.test.ts`, `tests/report-lint.test.ts`, `tests/security.test.ts`, `tests/service-worker.test.ts`, `tests/fixtures/reports/*.md` | `tests/advisory.test.ts`（1 件）、`tests/detection.test.ts`（1 件）、`tests/export.test.ts`（1 件）、`tests/fixtures/reports/*.md`（4 ファイル） | AngularJS 等 `fixed`/`none` 混在時の件数分離推奨文、KEV の CVE ID 名指し、HSTS `preload` 条件と 1 日未満 `MEDIUM`、証明書検証対象外の明記、診断項目名の統一と許容設定互換、CLR 2.0 の `Unknown` 修正 |
| T12 | — | 完了 | `b982d08` | `tests/advisory-db-invariants.test.ts`, `tests/spec-integrity.test.ts` | `tests/advisory-db-invariants.test.ts`（1 件） | 仕上げ（版表記 `1.7.1` 統一、仕様書・保守ガイド・README 同期） |

## 4. テスト結果

| コマンド | 結果 | 件数・要点 |
| --- | --- | --- |
| `npm test`（vitest） | PASS | passed 588 / skipped 0 / failed 0 |
| `npm run reports:lint` | PASS | 検査項目 9 / 9 合格、保留 0 件（T03 で保留とした R04・R08 は T05 で保留解除、T10 で R09 を追加。回帰用フィクスチャ全 4 組が合格） |
| `npm run build` | PASS | content-script 11.01 KB、service-worker 218.55 KB、dist 合計 822.01 KB |
| 同梱 DB | PASS | 収録 416 件、minExtensionVersion 1.7.0、dataVersion 20261031、schemaVersion 2.2、fixStatus 内訳 fixed 299 / partial 9 / none 12 / unknown 96、サイズ 451.88 KB |
| `npm run test:e2e` | 未実行（夜間モード。人間が確認） | テスト用サーバーの再現エンドポイント 4 件・スナップショット配信・Bootstrap 6 否定コントロールは実装済み。実機確認は人間が実施 |
| `node scripts/dev/check-v1.7.1.mjs` | FAIL（24 PASS / 1 FAIL / 0 WARN） | C08 は本報告書の作成で解消（スクリプトが再チェック）。WARN の項目は 0 件（なし） |

- v1.7.0 ベースライン: passed 431 / skipped 0 / failed 0
- skip 中のテスト（REPORT_DATA.json の vitest.skipped をそのまま転記。0 件なら「なし」）:
  - なし
- 期待値を変えた既存テスト（全件。受け入れテスト `tests/review-v1.6.5-acceptance.test.ts` の変更は 0 件）:
  - `tests/markdown.test.ts`（「Cookie値（Value）や機密トークンがレポートに含まれないこと」）— 指摘 7（T02）によりコードスパン内で `escapeMarkdown` を使わない仕様に変更したため、Cookie 名 `SESSION_ID` の出力期待値を `SESSION\_ID` から `` `SESSION_ID` `` に変更。
  - `tests/report-lint.test.ts`（保留項目の既定値検証テスト、T05）— T05 の受け入れ条件に従い整合性チェッカーの `(4) R04` と `(8) R08` の保留を解除したため、`getPendingChecks()` の期待値を `['R04', 'R08']` から `[]` に変更。
  - `tests/fixtures/reports/*.md`（`app-insights-cookies.md`、`csp-frame-ancestors.md`、`relative-urls-only.md`、`wordpress-legacy-ga.md` の 4 ファイル、T05・T09・T10・T11）— 指摘 N1（セクション 9 見出し・説明文）、指摘 K/E4/E5（WordPress 根拠整理・プラグイン/テーマ一覧・廃止済み GA タグ `INFO`）、指摘 3（セクション 8 CSP 問題点表）、指摘 N12（セクション 15 第 5 項の証明書検証対象外）の Markdown 出力仕様変更に伴い、`generateMarkdownReport(report)` 一致検証用のゴールデンファイルを同期。
  - `tests/cookies.test.ts`（「Cookie名に基づいて正しいカテゴリに分類されること」、T07）— T07 の仕様（`advertising` 用途の追加と広告 Cookie 対応表）に従い、`classifyCookie('_fbp')` の期待値を `'analytics'` から `'advertising'` に変更。
  - `tests/spec-integrity.test.ts`（「ルール定義と仕様書カタログの登録技術数が完全に一致すること」、T08・T09）— T08 で 4 技術（`Tomcat`、`Classic ASP`、`Azure Application Gateway`、`Application Insights`）、T09 で 1 技術（`Facebook SDK`）を追加したため、登録技術数の期待値を `70` → `74` → `75` に更新。
  - `tests/csp-parser.test.ts`（「`script-src` に `'unsafe-inline'` のみがある場合にMediumリスク（最大MEDIUM: E1）を返却すること」、T10）— E1（CSP の指摘は最大 MEDIUM）に従い、`inlineIssue?.severity` の期待値を `'high'` から `'medium'` に変更。
  - `tests/csp-parser.test.ts`（「`T06 / T10 (E1): script-src 'self' *.cdn.example および script-src https: はいずれも最大重大度 medium として検出されること`」、T10）— E1 に従い、任意ホスト許可 `script-src https:` に対する `httpsIssue?.severity` および `httpsEval.results[0].severity` の期待値を `'high'` から `'medium'` に変更。
  - `tests/report-lint.test.ts`（正常系検査および検査項目定義数のテスト 2 件、T10）— T10 の受け入れ条件に従い `scripts/report-lint.mjs` に検査項目 `(9) R09` を追加したため、`result.results.length` と `CHECK_DEFINITIONS.length` の期待値を `8` から `9` に変更。
  - `tests/advisory.test.ts`（ASP.NET CLR 2.0 / 4.0 判定テスト、T11）— T11 の「CLR 2.0 の EOL 判定の取り消し（T08 の修正）」に従い、CLR 2.0（`2.0.50727`）の `eolInfo.status` の期待値を `'EOL'`（`eolDate: '2016-04-12'`）から `'Unknown'`（`eolDate: null`、詳細にサポート期限 2 件を記載）に変更。
  - `tests/detection.test.ts`（`testaspnet.vulnweb.com.json` スナップショット検証テスト、T11）— 同上、T11 における CLR 2.0 の `Unknown` 化に伴い、`aspnet?.supportStatus` の期待値を `'EOL'` から `'Unknown'` に変更。
  - `tests/export.test.ts`（「`T02 (SPEC-13 / IMPL-02): エクスポート 3 形式 (JSON / CSV / Markdown) すべてに fixStatus と kev が出力される`」、T11）— T11 指摘 E により KEV 該当 CVE ID を名指し表示する仕様に変更したため、CSV・Markdown の KEV 列期待値を `CISA KEV: CVE-2020-11023` 表記に変更。
  - `tests/advisory-db-invariants.test.ts`（「`T05 (P1): NVD 自動取り込みが有効化され、minExtensionVersion が 1.7.0 であり...`」、T12）— T12 の版上げに従い `manifestJson.version` の期待値を `'1.7.0'` から `'1.7.1'` に変更（`advisoryDbJson.minExtensionVersion` の `'1.7.0'` は変更なし）。

## 5. 変更の概要（利用者から見た変化）

- **要確認件数・重大度内訳・ステータス表示の完全一致化（T01）**: `info` ステータスの項目が Markdown 等で `WARN` と表示されなくなり、サマリーの CRITICAL〜LOW の合計が常に「要確認」の件数と一致するようになりました（`INFO` 行は `pass` と `info` の合計件数として「参考情報・問題のない項目」を表示）。また `Referrer-Policy` 未設定はブラウザ既定値が安全であるため `info` となり、既知脆弱性の観測値末尾の閉じ括弧欠落も解消しました。
- **推奨対応ロードマップの動的化と Markdown 表示品質の改善（T02）**: 固定文だったロードマップを撤廃し、実際に検出された「要確認」の指摘のみから重大度別に自動生成します（0 件なら「対応が必要な項目はありません。」と表示）。コードスパン内の不要なバックスラッシュ（`SESSION\_ID` 等）をなくし、前回との比較を行っていない場合の差分原因欄を「比較未実行のため対象外」に整理し、EOL・脆弱性表から内部表記 `Rev.2.1` や LTS を持たない技術への「最新LTS系列」表記、バージョン不明時の「現状維持」表記を除去しました。Cookie 節には親ドメインの Cookie に関する注記を追加しました。
- **実際の読み込みリソースに基づく外部通信先分析への刷新（T05）**: DOM 属性の単純収集から、`performance.getEntriesByType('resource')` による実読み込みリソース（および `document.baseURI` 基準で絶対 URL 解決した読み込み対象 DOM 要素＋メイン文書）の集計に改めました。相対パスのみのサイトでも自ホストが正しく計上され、`hreflang` 等の `alternate` リンクや `form` の送信先だけで通信先に計上される誤りが解消しました。サンプル URL もクエリ・フラグメントがマスクされます。
- **調査完全性の精度向上と混在コンテンツの要素・URL 表示（T06）**: DOM シグナル収集件数の算定対象を拡充し、Content Script の収集途中失敗時や DOM に参照があるのに通信先が 0 件の場合に完全性を「部分的」として理由を表示します。混在コンテンツの指摘には `script: http://...` や `form[action]: http://...` のように対象要素とマスク済み URL（最大 3 件＋他 N 件）を表示します。
- **Cookie の 6 用途分類と一般 Cookie 検査の独立化（T07）**: 用途に「広告・マーケティング（`advertising`）」と「同意管理（`consent`）」を追加し、Application Insights（`ai_session`・`ai_user`）や `__RequestVerificationToken` 等の既知 Cookie 名対応表を拡充しました。認証系 Cookie の指摘がある場合でも一般 Cookie の `Secure` 欠落チェックが独立して出力され、HTTP ページでは PASS 観測値に「HTTP のため Secure は評価対象外」と明記されます。
- **サーバー・基盤・フロント・CMS・計測タグの検出精度向上と根拠整理（T08, T09）**:
  - `x-vercel-id` 等の無関係なヘッダーから Fedora 等のディストリ版を誤検出しなくなりました。
  - `Tomcat`（および連動 `Java`）、`Classic ASP`、`Azure Application Gateway`、`Application Insights`、`Facebook SDK`、GTM `gtag/js` の検出と、廃止済み旧 GA タグ（`ga.js`・`analytics.js`）への `INFO` 指摘に対応しました。
  - `ASP.NET` と `Spring Security` を「フレームワーク」カテゴリへ整理し、確信度が `medium` 以下の技術を「稼働確認済」と断定しないようにしました。`X-AspNet-Version` は CLR 版として分かりやすく表示し、ヘッダー露出を `LOW` 指摘として報告します。
  - Bootstrap 6 のレスポンシブクラス（`lg:d-none` 等）を Tailwind CSS と誤認しなくなりました。
  - WordPress では `wp-includes/` 配下のコア `ver` からの版抽出と、検出したプラグイン・テーマおよび `ver` の一覧表示に対応しました。また検出根拠の重複を統合し、画面と Markdown では技術ごとに代表 3 件＋「他 ○ 件」に整理しました。
- **CSP の重大度上限（最大 MEDIUM）・積集合評価・ポリシー別問題点表の追加（T10）**: CSP があるページの評価が CSP 未設定（`MEDIUM`）より重くならないよう CSP 指摘の最大重大度を `MEDIUM` に統一し、`style-src` のみの `'unsafe-inline'` は `INFO` としました。ヘッダーと `meta` の複数強制 CSP を能力単位の積集合で評価し、観測値に問題点の要約、Markdown の CSP 節にディレクティブ別の問題点表を表示します。`X-Frame-Options` と `frame-ancestors` の内容が異なる場合は `frame-ancestors` が優先される旨の `INFO` 注記を出します。
- **修正版有無の内訳表示・CISA KEV の名指し・HSTS preload 条件・証明書対象外の明記・診断項目名の統一（T11）**:
  - AngularJS 等で修正版ありの CVE と修正版なしの CVE が混在する場合、「最終版 1.8.3 で ○ 件解消、残り ○ 件は修正版なし（移行か緩和策）」のように内訳を表示します。
  - CISA KEV 該当時は `CISA KEV: CVE-2020-11023` のように該当 CVE ID を名指しし、他の CVE と混同されないようにしました。
  - HSTS で `max-age` が 1 日未満の場合は `MEDIUM`、`preload` 指定時に `max-age` 1 年未満または `includeSubDomains` 未指定の場合は登録条件未達の `INFO` を出力します。また HTTPS 接続の観測値と制限事項に「証明書の有効性は対象外」を明記しました。
  - セキュリティ診断の固定項目名を status によらず以下の正規名称に統一しました（旧名称で保存された許容設定もそのまま有効です）:

| checkId プレフィックス | 統一後の正規項目名 | 旧名称（許容設定の互換維持対象） |
| --- | --- | --- |
| `SEC-XFO-*` | `X-Frame-Options` | `X-Frame-Options (CSP frame-ancestors により保護)`、`X-Frame-Options 未設定` |
| `SEC-HTTPS-*` | `HTTPS暗号化通信` | `暗号化通信未適用 (平文HTTP接続)` |
| `SEC-CORS-*` | `CORS (Cross-Origin Resource Sharing)` | `CORS設定 (クロスオリジン許可)` |
| `SEC-REF-*` | `Referrer-Policy` | `Referrer-Policy (無効な設定値)`、`Referrer-Policy (unsafe-url)`、`Referrer-Policy (no-referrer-when-downgrade)` |
| `SEC-HSTS-*` | `HSTS (Strict-Transport-Security)` | （変更前から統一済み） |
| `SEC-XCTO-*` | `X-Content-Type-Options` | （変更前から統一済み） |
| `SEC-PERM-*` | `Permissions-Policy` | （変更前から統一済み） |
| `SEC-CSP-00〜03` | `CSP (Content-Security-Policy)` | （変更前から統一済み） |

## 6. 指示からの逸脱・判断事項

| 箇所 | 指示 | 実際に行ったこと | 理由 |
| --- | --- | --- | --- |
| T01 | 既知脆弱性の観測値の閉じ括弧の漏れを直す | Markdown 出力（`src/export/markdown.ts`）とポップアップ行描画（`src/popup/render.ts`）で行っていた固定文字数（60 文字・42 文字）での `observed` 切り詰め処理を廃止した | CISA KEV 該当時の `SEC-CVE-*` の観測値（61 文字）が 60 文字目で切断されて末尾の `)` が欠落していたのが根本原因であり、固定長切り詰めをやめることで全項目で括弧欠落を防止できるため。 |
| T05 | メイン文書・DOM 参照・Resource Timing の組み合わせ方 | `performance.getEntriesByType('resource')` を主としつつ、`noscript` / `template` 内を除いた読み込み対象 DOM 要素（`baseURI` 基準の絶対 URL）で補完し、メイン文書 URL 自体も自ホスト 1 件として計上した | サブリソースを一切持たない単一 HTML ページ（`http.badssl.com` 等）やヘッドレス環境でも、自ホスト通信が 0 件にならず実態と整合させるため。 |
| T06 | N2 の 3 サイト（`angular.dev`、`angularjs.org`、`www.drupal.org`）の検出確認 | `angular.dev` は正規表現修正によりスナップショットから検出を確認。`angularjs.org` と `www.drupal.org` はスナップショット応答自体が 404 エラーページ・Fastly チャレンジページで技術の印が無いため、通常ページ向けの代替シグナルと否定コントロールを追加し、タスク状態を「一部完了」とした | 指示書 T06 の受け入れ条件「印が無いと分かった場合は、その根拠（HTML の該当箇所）を完了報告書に書き、「一部完了」とする」に忠実に従うため。 |
| T08 / T11 | ASP.NET CLR 2.0 系の EOL 判定と `catalog.json` / `eol.mjs` の扱い | T08 では `advisory-db.json` の不変条件（`catalog.json` の全製品は CVE 1 件以上を持つ必要がある）を壊さないよう `src/detection/advisory.ts` で CLR 2.0 を EOL とし、続く T11 の指示に従って EOL 判定を取り消し `Unknown`（詳細に 2.0/3.0 と 3.5 SP1 の期限を併記）に修正した | `catalog.json` に CVE のない製品を追加すると DB 検証が不合格になるため `advisory.ts` で扱い、最終的には T11 の仕様どおり安全側の `Unknown` としたため。 |
| T10 | X-Frame-Options と `frame-ancestors` の矛盾に対する INFO 注記の ID・項目名 | `checkId` を `SEC-CSP-XFO-CONFLICT`、項目名を `CSP (frame-ancestors と X-Frame-Options の優先関係)` とした | `SEC-XFO-*` プレフィックスにすると整合性チェッカー R05（`SEC-XFO-*` の項目名は `X-Frame-Options` で統一）および同一表内の重複項目名と干渉するため、独立した補足注記 ID として分離した。 |
| T11 | status で名前が変わる項目の洗い出しと統一 | 明示された `SEC-HTTPS-01` と `SEC-CORS-01/02` に加え、`SEC-REF-02`（無効値・`unsafe-url`）と `SEC-REF-03`（`no-referrer-when-downgrade`）も `Referrer-Policy` に統一し、違いは `observed` に出力した | 指示書 T11 の「ほかに status で名前が変わる項目があれば同じように揃え、完了報告書に一覧を書く」に従い、全固定診断項目を点検して統一したため。 |

## 7. 未解決の問題・既知の制限

- **T06（一部完了）— スナップショット 2 サイトにおけるサイト側応答起因の未検出**:
  - `angular.dev` のスナップショットでは Angular `22.2.5` が正常に検出されるようになったが、残り 2 サイトのスナップショットには取得時の応答自体に当該技術の印が含まれていないため、スナップショット単体からは検出できない:
    1. **`angularjs.org`**: `tests/fixtures/snapshots/angularjs.org.json`（`statusCode: 404`）および `tests/fixtures/snapshots/angularjs.org.html`（全 104 行）は、7 行目の `title` 要素 `Site Not Found`、95 行目の `404`、96 行目の `Site Not Found`、99 行目の Firebase Hosting ドキュメント案内からなる Firebase Hosting の既定 404 エラーページであり、HTML・ヘッダー・Resource Timing のいずれにも AngularJS の属性やスクリプトが存在しない。
    2. **`www.drupal.org`**: `tests/fixtures/snapshots/www.drupal.org.html`（全 1 行）は、`title` 要素 `Client Challenge`、`id="fastlyLogo"` の Fastly ロゴ画像、`id="captchaTitle"` の文字入力案内からなる Fastly の Bot / CAPTCHA チャレンジ（Client Challenge）インタースティシャルページであり、HTML・ヘッダー・Resource Timing のいずれにも Drupal の属性やパスが存在しない。
  - 対応状況: 通常の AngularJS ページおよび Drupal ページで観測される代替シグナルと、誤検出防止の否定コントロールは実装・単体テスト済み。実ブラウザで通常ページが表示された状態での確認は §8 で人間が実施する。
- **失敗しているテスト**: なし（`vitest` は passed 588 / skipped 0 / failed 0、`reports:lint` は全 9 項目合格、総合チェックは完了報告書作成前の C08 を除く全 24 項目が PASS）。
- **未実行のテスト（夜間モード対象外）**: `npm run test:e2e`（`node scripts/dev/check-v1.7.1.mjs --e2e`）および実サイトに対する `npm run reports:collect`。
- **仕様上の既知の制限（v1.7.1 スコープ外）**:
  - WordPress のプラグイン・テーマは名前と `ver` の一覧表示のみであり、脆弱性 DB との照合は行わない（E4、v1.8 以降の対象）。
  - TLS/SSL 証明書の有効期限・失効状態・信頼チェーンは Web 拡張機能の受動的 API からは取得できないため診断対象外としている（レポートの観測値およびセクション 15 の制限事項に明記済み）。

## 8. 人間の確認が必要な事項

- [ ] 実サイト（公開テストサイトと実サイト）のレポートを取り直し、レビューの各指摘が解消したことの確認（`npm run reports:collect -- --sites scripts/report-sites.example.txt --timeout 90000` および `npm run reports:collect`）
- [ ] ポップアップ・ダッシュボードの目視確認（ステータス表示、動的ロードマップ、通信先、Cookie の 6 用途、CSP の問題点の表、WordPress のプラグイン・テーマ一覧）
- [ ] E2E（`KIT_SRC=~/patches/v1.7.1-kit node scripts/dev/check-v1.7.1.mjs --e2e`）の実行
- [ ] T05 で収集内容が変わったことに伴う `PRIVACY_POLICY.md` の文言承認と、Chrome Web Store のデータ開示・説明文の見直し（v1.7.0 の content script オンデマンド注入の変更と合わせて）:
  - **変更箇所 1（第 2 章 Content Scripts 項目 — 英語・日本語）**:
    - 英語（更新後）: `Content scripts are injected on demand via chrome.scripting.executeScript only when the user initiates an inspection, and only analyze the DOM and the browser's Performance Resource Timing API (performance.getEntriesByType('resource')) at that time. The full HTML text and user input forms are never saved. Only technical signatures (meta tags, script/stylesheet/resource URLs and initiator types, CSS utility class names) are evaluated in memory, and sample resource URLs stored in reports have query strings and fragments removed.`
    - 日本語（更新後）: `コンテンツスクリプトはユーザーが調査を実行したときにのみ chrome.scripting.executeScript によって対象タブへオンデマンド注入され、その時点でのみ DOM および Performance Resource Timing API（performance.getEntriesByType('resource')）による読み込み済みサブリソース一覧（URLおよび initiatorType）を解析します。ページのHTML全文やユーザーの入力フォームは保存せず、技術的な特徴（metaタグ、スクリプト・スタイルシート・読み込み済みリソースのURL、CSSクラス名など）のみをメモリ上で受動的に評価します（外部通信先のサンプルURLをレポートへ記録する際もクエリ文字列とフラグメントは除去・マスクされます）。`
  - **変更箇所 2（第 4 章 `activeTab` / `scripting` の用途説明 — 英語・日本語）**:
    - 英語（更新後）: `To analyze DOM signatures (meta tags, script URLs, mixed content) and loaded resource URLs via the Performance Resource Timing API (performance.getEntriesByType('resource')) of the active tab. Content scripts are injected on demand only when the user initiates an inspection.`
    - 日本語（更新後）: `アクティブなタブのDOM特徴、混在コンテンツ、および Performance Resource Timing API（performance.getEntriesByType('resource')）で観測された読み込み済みリソースURLを受動的に分析します。コンテンツスクリプトはユーザーが調査を実行したときにのみオンデマンドで注入され、DOM を解析します。`
- [ ] T06 の調査結果（`angular.dev`・`angularjs.org`・`www.drupal.org` で検出されなかった原因と、行った対応）の確認:
  - **`angular.dev`**: スナップショット（`angular.dev.html` 293 行目）に `ng-version="22.2.5+sha-d881689"`、`ng-server-context="ssg"`、`_nghost-ng-c1178817259=""` が存在していたが、`frontend.json` の `[ng-version]` 正規表現が `ng-version="([0-9.]+)"` でビルドメタデータ `+sha-...` に対応していなかったことが原因。正規表現をプレリリース・ビルドメタデータ対応に修正し、`angular.dev` スナップショットから Angular `22.2.5`（確信度 95）が検出されることを確認済み。さらに `ng-version` を出さない本番ビルド向けに `_nghost-*` / `_ngcontent-*` / `[ng-server-context]` を代替シグナルとして追加した。
  - **`angularjs.org`**: スナップショット（`angularjs.org.json` の `statusCode: 404`、`angularjs.org.html` 7 行目 `Site Not Found`、95〜99 行目の Firebase Hosting 404 エラー案内）自体が 404 エラーページであり、AngularJS の印やスクリプトが含まれていなかったことが原因。ルールには `[data-ng-app]`、`[data-ng-controller]`、`[ng-model]`、`[data-ng-model]`、`[ng-bind]`、`[ng-repeat]`、`[ng-cloak]`、`.ng-scope`、`.ng-binding` と否定コントロールを追加済み。サイト移転または配信状態の確認を推奨。
  - **`www.drupal.org`**: スナップショット（`www.drupal.org.html` 1 行目 `Client Challenge`、`id="fastlyLogo"`、`id="captchaTitle"`）自体がヘッドレスアクセスに対する Fastly の Bot / CAPTCHA チャレンジページであり、Drupal の印が含まれていなかったことが原因。ルールと Content Script には `x-drupal-dynamic-cache` ヘッダー、`data-drupal-*` 属性接頭辞探査、`/core/misc/drupal.js`・`/core/themes/` パスと否定コントロールを追加済み。通常のブラウザ操作でチャレンジ通過後のページを診断して検出されることの確認を推奨。
- [ ] T08 / T11 における ASP.NET の CLR 2.0 系の EOL 扱いと根拠の確認:
  - 最終的な実装: **EOL と断定せず `Unknown` とした**（T08 で一旦 `eolDate: '2016-04-12'` の EOL として実装したが、T11 の指示により取り消して `Unknown` に修正済み。`X-AspNet-Version` の露出指摘 `SEC-DISC-03` は `LOW` として継続）。
  - 参照先と日付: Microsoft Lifecycle Policy — Microsoft .NET Framework（[https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework](https://learn.microsoft.com/en-us/lifecycle/products/microsoft-net-framework)）。CLR 2.0（`2.0.50727`）を共有する `.NET Framework 2.0 / 3.0` は **2011-07-12** にサポート終了している一方、`.NET Framework 3.5 SP1` は **2029-01-09** までサポートが継続されており、`X-AspNet-Version` ヘッダーだけでは判別できないため、詳細欄に両者の日付を併記して安全側の `Unknown` とした。
- [ ] curated と上流の乖離（`REPORT_DATA.json` の `advisoryDrift` 全 11 件、v1.7.0 時点で維持判断済みの継続確認）:

| 製品 | ID | curated の範囲 | 上流の範囲 | curated の CVSS | 上流の CVSS | 取得元 |
| --- | --- | --- | --- | --- | --- | --- |
| jquery | CVE-2019-11358 | &lt; 3.4.0 | &gt;= 1.1.4, &lt; 3.4.0 | 6.1 | 6.1 | osv |
| jquery | CVE-2020-11022 | &gt;= 1.2.0, &lt; 3.5.0 | &gt;= 1.12.0, &lt; 3.5.0 | 6.1 | 6.1 | osv |
| jquery | CVE-2015-9251 | &lt; 3.0.0 | &lt; 1.12.2 \|\| &gt;= 1.12.3, &lt; 3.0.0 | 6.1 | 6.1 | osv |
| bootstrap | CVE-2019-8331 | &lt; 3.4.1 \|\| &gt;= 4.0.0, &lt; 4.3.1 | &gt;= 3.0.0, &lt; 3.4.1 \|\| &gt;= 4.0.0, &lt; 4.3.1 | 6.1 | 6.1 | osv |
| lodash | CVE-2020-8203 | &lt; 4.17.20 | &gt;= 3.7.0, &lt; 4.17.19 | 7.4 | 7.4 | osv |
| php | CVE-2024-4577 | &lt; 8.1.29 \|\| &gt;= 8.2.0, &lt; 8.2.20 \|\| &gt;= 8.3.0, &lt; 8.3.8 | &gt;= 8.1.0, &lt; 8.1.29 \|\| &gt;= 8.2.0, &lt; 8.2.20 \|\| &gt;= 8.3.0, &lt; 8.3.8 | 9.8 | 9.8 | nvd |
| nginx | CVE-2023-44487 | &gt;= 1.9.5, &lt; 1.25.3 | &gt;= 1.9.5, &lt;= 1.25.2 | 7.5 | 7.5 | nvd |
| apache | CVE-2021-42013 | &gt;= 2.4.49, &lt;= 2.4.50 | = 2.4.49 \|\| = 2.4.50 | 9.8 | 9.8 | nvd |
| laravel | CVE-2018-15133 | &lt; 5.5.41 \|\| &gt;= 5.6.0, &lt; 5.6.30 | &lt;= 5.5.40 \|\| &gt;= 5.6.0, &lt; 5.6.30 | 8.1 | 8.1 | osv |
| nodejs | CVE-2023-23918 | &gt;= 14.0.0, &lt; 14.21.3 \|\| &gt;= 16.0.0, &lt; 16.19.1 \|\| &gt;= 18.0.0, &lt; 18.14.1 \|\| &gt;= 19.0.0, &lt; 19.6.1 | &gt;= 14.0.0, &lt;= 14.14.0 \|\| &gt;= 14.0.0, &lt; 14.21.3 \|\| &gt;= 16.0.0, &lt;= 16.12.0 \|\| &gt;= 16.0.0, &lt; 16.19.1 \|\| &gt;= 18.0.0, &lt;= 18.11.0 \|\| &gt;= 18.0.0, &lt; 18.14.1 \|\| &gt;= 19.0.0, &lt; 19.6.1 | 7.5 | 7.5 | nvd |
| nodejs | CVE-2023-39332 | &gt;= 20.0.0, &lt; 20.8.1 | &gt;= 20.0.0, &lt; 20.8.0 | 9.8 | 9.8 | nvd |

- [ ] PR の作成・レビュー・マージ、および v1.7.1 の Chrome Web Store への提出と公開

## 9. 変更ファイル一覧

```
 .gitignore                                         |    4 +
 PRIVACY_POLICY.md                                  |    6 +-
 README.md                                          |  134 ++-
 dashboard.html                                     |    2 +-
 docs/DETECTION_SPECIFICATION.md                    |  191 ++--
 docs/MAINTENANCE_GUIDE.md                          |  133 ++-
 docs/dev/v1.7.1/WORKLOG.md                         |  189 ++++
 package-lock.json                                  |    4 +-
 package.json                                       |    4 +-
 popup.html                                         |    2 +-
 public/manifest.json                               |    2 +-
 scripts/collect-reports.mjs                        |  569 ++++++++++
 scripts/report-lint.mjs                            | 1157 ++++++++++++++++++++
 scripts/report-sites.example.txt                   |   36 +
 scripts/test-e2e-smoke.mjs                         |   39 +
 src/background/service-worker.ts                   |  187 +++-
 src/content/content-script.ts                      |  683 ++++++++----
 src/content/dom-selectors.generated.ts             |   16 +
 src/dashboard/dashboard.ts                         |   97 +-
 src/dashboard/render.ts                            |  205 +++-
 src/detection/advisory.ts                          |  140 ++-
 src/detection/engine.ts                            |  652 +++++++++--
 src/detection/rules/backend.json                   |   77 +-
 src/detection/rules/cms.json                       |   33 +-
 src/detection/rules/frontend.json                  |   25 +-
 src/detection/rules/index.ts                       |    4 +-
 src/detection/rules/language.json                  |   47 -
 src/detection/rules/server.json                    |   26 +-
 src/detection/rules/services.json                  |   64 +-
 src/export/csv.ts                                  |   16 +-
 src/export/markdown.ts                             |  361 ++++--
 src/popup/popup.ts                                 |   51 +-
 src/popup/render.ts                                |   78 +-
 src/security/cookies.ts                            |  207 +++-
 src/security/csp-parser.ts                         |  369 ++++++-
 src/security/domain-analyzer.ts                    |  330 +++++-
 src/security/engine.ts                             |   12 +-
 src/security/headers.ts                            |  113 +-
 src/security/https.ts                              |   64 +-
 src/security/version-matcher.ts                    |    4 +-
 src/shared/coverage.ts                             |  137 ++-
 src/shared/security-status.ts                      |  212 ++++
 src/shared/types.ts                                |   61 +-
 src/storage/exceptions.ts                          |   76 +-
 src/storage/history.ts                             |   54 +-
 test-server/server.mjs                             |  241 ++++
 tests/advisory-db-invariants.test.ts               |    2 +-
 tests/advisory.test.ts                             |   74 ++
 tests/content-script.test.ts                       |  662 +++++++++++
 tests/cookies.test.ts                              |  299 ++++-
 tests/coverage.test.ts                             |   90 ++
 tests/csp-parser.test.ts                           |  282 ++++-
 tests/dashboard-history.test.ts                    |  111 +-
 tests/detection.test.ts                            |  863 +++++++++++++++
 tests/domain-analyzer.test.ts                      |  173 +++
 tests/exceptions.test.ts                           |   79 ++
 tests/export.test.ts                               |    4 +-
 tests/fixtures/.gitignore                          |    2 +
 tests/fixtures/dom-signal-fixtures.ts              |    6 +
 tests/fixtures/reports/app-insights-cookies.json   |  292 +++++
 tests/fixtures/reports/app-insights-cookies.md     |  157 +++
 tests/fixtures/reports/csp-frame-ancestors.json    |  215 ++++
 tests/fixtures/reports/csp-frame-ancestors.md      |  158 +++
 tests/fixtures/reports/relative-urls-only.json     |  247 +++++
 tests/fixtures/reports/relative-urls-only.md       |  159 +++
 tests/fixtures/reports/wordpress-legacy-ga.json    |  296 +++++
 tests/fixtures/reports/wordpress-legacy-ga.md      |  160 +++
 tests/fixtures/snapshots/angular.dev.html          |  314 ++++++
 tests/fixtures/snapshots/angular.dev.json          |  469 ++++++++
 tests/fixtures/snapshots/angularjs.org.html        |  104 ++
 tests/fixtures/snapshots/angularjs.org.json        |   67 ++
 tests/fixtures/snapshots/demo.testfire.net.html    |  161 +++
 tests/fixtures/snapshots/demo.testfire.net.json    |  121 ++
 tests/fixtures/snapshots/getbootstrap.com.html     |  129 +++
 tests/fixtures/snapshots/getbootstrap.com.json     |  283 +++++
 tests/fixtures/snapshots/http.badssl.com.html      |   19 +
 tests/fixtures/snapshots/http.badssl.com.json      |   58 +
 .../fixtures/snapshots/mixed-form.badssl.com.html  |   24 +
 .../fixtures/snapshots/mixed-form.badssl.com.json  |   58 +
 .../snapshots/mixed-script.badssl.com.html         |   25 +
 .../snapshots/mixed-script.badssl.com.json         |   76 ++
 tests/fixtures/snapshots/mixed.badssl.com.html     |   22 +
 tests/fixtures/snapshots/mixed.badssl.com.json     |   67 ++
 tests/fixtures/snapshots/react.dev.html            |   99 ++
 tests/fixtures/snapshots/react.dev.json            |  681 ++++++++++++
 tests/fixtures/snapshots/testasp.vulnweb.com.html  |   43 +
 tests/fixtures/snapshots/testasp.vulnweb.com.json  |   73 ++
 .../fixtures/snapshots/testaspnet.vulnweb.com.html |   85 ++
 .../fixtures/snapshots/testaspnet.vulnweb.com.json |   94 ++
 tests/fixtures/snapshots/wordpress.org.html        |  933 ++++++++++++++++
 tests/fixtures/snapshots/wordpress.org.json        |  516 +++++++++
 tests/fixtures/snapshots/www.drupal.org.html       |   78 ++
 tests/fixtures/snapshots/www.drupal.org.json       |  154 +++
 tests/markdown.test.ts                             |  536 ++++++++-
 tests/report-lint.test.ts                          |  867 +++++++++++++++
 tests/security.test.ts                             |  570 +++++++++-
 tests/service-worker.test.ts                       |  270 +++++
 tests/spec-integrity.test.ts                       |   66 +-
 98 files changed, 17547 insertions(+), 960 deletions(-)
```

## 10. 次回（v1.8.x）への申し送り

- **WordPress プラグイン・テーマの脆弱性照合（E4）**: v1.7.1 では `wp-content/plugins/` および `wp-content/themes/` から名前と `ver` を抽出して一覧表示するところまで実装した。v1.8 以降でプラグイン・テーマ向けの脆弱性データソース選定とオフライン DB スキーマ拡張を検討する。
- **`version-matcher` のプレリリース識別子拡張**: 現時点で主要な SemVer プレリリース比較には対応済みだが、より特殊なベンダ固有プレリリース表記への対応余地がある。
- **`DetectionEngine` 単体テストでの固定 DB 既定化**: v1.7.0 からの継続課題として、テスト共通セットアップで `advisory-db.fixture.json` を既定化する仕組みを入れると、将来の DB 自動更新に対する単体テストの独立性がさらに高まる。
- **WAF / Bot チャレンジ画面応答時の状態通知の高度化**: `www.drupal.org` のスナップショットで確認されたように、自動収集や一部のアクセス環境で Fastly Client Challenge や Cloudflare Turnstile 等のインタースティシャル応答が返った場合、対象サイト本体の技術ではなくチャレンジ画面のみを評価していることを利用者に分かりやすく伝える補助表示を検討する余地がある。
