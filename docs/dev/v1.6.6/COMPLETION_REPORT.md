# v1.6.6 完了報告書

## 1. サマリー

- 作業期間: 2026-10-31 〜 2026-10-31
- ブランチ / 最終コミット: `feature/v1.6.6` / 本報告書を更新したコミット（`[T12] 完了報告書の修正（T09 の残作業、E2E の結果）`）
- 結果: 完了 12 / 一部完了 0 / 未完了 0（全 12 タスク）
- 総合チェック（`node scripts/dev/check-v1.6.6.mjs --e2e`）: PASS（19 PASS / 0 FAIL。E2E を含む）
- 一言で: v1.6.5 レビュー指摘の P0 受け入れテスト全 7 件を解消した。主な内容は、ヘッダー未観測時の安全な表示、EOL 既定値と解析不能バージョンの是正、ディストリ版の Needs Review 化、主要 5 ルールの誤検知の解消、DOM シグナルの到達性確保、Lodash / Moment.js の追加、UI の XSS 対策、旧 DB・旧エンジンの廃止、v1.6.6 へのバージョン統一。残るのは、プライバシーポリシー（T10）の文言承認と、ポップアップ・ダッシュボードの目視確認（人間の確認事項）。

> [!NOTE]
> 本作業は夜間（無人）モードで実施。コーディングは AI コーディングエージェント、テストとコミットは夜間スクリプト（scripts/dev/overnight.sh）がサンドボックスの外で実行（2026-10-31 10:22〜13:00）。
> 夜間実行の後、人間が次を行った: サンドボックスでは削除できなかった旧 DB・旧エンジンのファイルの削除（T09）、E2E スモークテストの実行、本報告書の更新。

## 2. 実行環境

| 項目 | 値 |
| --- | --- |
| OS | macOS 27.0.1 |
| Node.js / npm | v24.13.0 / 11.6.2 |
| AI コーディングエージェント / モデル | 1.4.12 / gemini-3.8-flash-high |
| Chrome（E2E） | Playwright の Chromium（人間が手元で実行。テスト用サーバー `npm run test-server` を別に起動） |

## 3. タスク別結果

| ID | 指摘ID | 結果 | コミット | 解除した受け入れテスト | 追加・変更したテスト | 備考 |
| --- | --- | --- | --- | --- | --- | --- |
| T01 | IMPL-01 | 完了 | 3e181db | — | `tests/dashboard-history.test.ts` | 履歴一覧の onclick 属性をイベント委譲に移行、描画関数を分離 |
| T02 | SPEC-01, IMPL-02, SPEC-16 | 完了 | 7eacbf8 | SPEC-01 | `tests/service-worker.test.ts` | オリジン不一致時の未観測化、プリレンダリング対応、未観測バッジ追加 |
| T03 | SPEC-04, SPEC-06, IMPL-04 | 完了 | 720abcf | SPEC-04, SPEC-06 | `tests/version-check.test.ts`, `tests/service-worker.test.ts` | EOL照合順序・既定値是正、解析不能バージョン処理、MAIN world値検証 |
| T04 | SPEC-02 | 完了 | 29d7f41 | SPEC-02 | `tests/detection.test.ts`, `tests/advisory.test.ts`, `tests/export.test.ts` | distroHint 導入、バックポート考慮の Needs Review 化、UI/エクスポート出力 |
| T05 | SPEC-09 | 完了 | bd075b1 | SPEC-09 | `tests/detection.test.ts` | Tailwind, Font Awesome, Chart.js, D3.js, Rails の誤検知を是正 |
| T06 | DOC-01 | 完了 | 3112d4a | DOC-01 | `tests/fixtures/dom-signal-fixtures.ts`, `tests/rule-reachability.test.ts`, `tests/spec-integrity.test.ts` | DOMセレクタ自動抽出、汎用収集、全26件のDOMシグナル到達性テスト |
| T07 | DOC-02 | 完了 | 1778976 | DOC-02 | `tests/detection.test.ts`, `tests/spec-integrity.test.ts` | Lodash, Moment.js ルール追加、Underscore 誤認防止ガード |
| T08 | IMPL-03 | 完了 | 84098be | — | `tests/ui-escaping.test.ts` | `src/shared/html.ts` 新設（escapeHtml/safeHref）、innerHTML エスケープ徹底 |
| T09 | DOC-09 | 完了 | e71732b ほか | — | `tests/version-check.test.ts` | 旧DB・旧エンジンの参照全廃と照合一本化。サンドボックスでは削除できなかったファイル4件は、人間が削除（`git rm -r src/security/cve src/security/eol`、コミット `[T09] 旧DB・旧エンジンのファイルを削除`） |
| T10 | DOC-08 | 完了 | 013966f | — | — | 実装整合化（Cookie値即時破棄、content script、webRequest許可リスト）。人間の承認待ち |
| T11 | — | 完了 | 11d4bd2 | — | `tests/dashboard-history.test.ts` | バージョン 1.6.6 統一、テスト件数・既知の制限・仕様書の整合 |
| T12 | — | 完了 | 7e4f0e7 | — | `test-server/server.mjs`, `scripts/test-e2e-smoke.mjs` | E2Eスモークテスト項目追加（Apache distro, Bootstrap only, ダッシュボード履歴操作&CSP監視） |

## 4. テスト結果

| コマンド | 結果 | 件数・要点 |
| --- | --- | --- |
| `npm test` | PASS | passed 317 / skipped 5 / failed 0 (3s) |
| `npm run build` | PASS | content-script サイズ 5.63 kB、service-worker サイズ 90.34 kB（旧エンジンの削除後） |
| `npm run advisories:validate` | PASS | 0s |
| `npm run advisories:verify-nvd` | PASS | 0s |
| `npm run test:e2e` | PASS | 人間が手元で実行（テスト用サーバーを別に起動）。T12 で追加した項目（/distro-apache、/bootstrap-only、ダッシュボードの履歴操作と CSP 違反の監視）を含め、スモークテストの全項目が成功 |
| `node scripts/dev/check-v1.6.6.mjs --e2e` | PASS | 19 PASS / 0 FAIL（C01〜C12、R01〜R07）。夜間実行の直後は C05（旧ファイルの残存）と C11（報告書の表記の誤判定）が FAIL だったが、人間の対応で解消 |

- v1.6.5 ベースライン: passed 216 / skipped 24
- 現在のテスト件数: passed 317 / skipped 5 / failed 0（全 322 テスト）
- 注記: 夜間実行の事前チェックでは、リポジトリ内に置かれていた v1.6.5 の展開フォルダ（`review/`、Git 管理外）のテストまで重複して数えられ、ベースラインが 390 件と表示されていた。フォルダをリポジトリの外へ移した後の件数（T01 の時点で 224 passed）が正しい値である。
- skip のまま残した受け入れテスト（P1 対象）: SPEC-07 / SPEC-08（同一ドメイン Cookie 判定: 2件）、SPEC-10（インラインスクリプトハッシュ評価: 2件）、SPEC-12（クエリパラメータ・フラグメント除外: 1件）（指示書に基づき P1 対象は v1.6.6 スコープ外として正当に残置）

## 5. 変更の概要（利用者から見た変化）

- **ヘッダー未観測時の安全な表示**: 拡張機能読み込み前やタブ URL とオリジン不一致時など、レスポンスヘッダーが未観測のタブでは、HSTS や CSP 等のヘッダー系セキュリティ診断項目が「未観測」（灰色バッジ）と表示され、誤って脆弱性警告（要確認件数）に含まれなくなりました。
- **ディストリビューション版パッケージの誤警告防止**: `Server: Apache/2.4.41 (Ubuntu)` や `PHP/8.1.2-1ubuntu2.14` のように OS 配布パッケージであることがヘッダーから判明した場合、アップストリームの公開バージョンのみに基づく断定的な EOL / 脆弱性警告を行わず、「ディストリ版（バックポートの可能性）」バッジとともに「Needs Review（要確認）」として安全に案内するようになりました。JSON、CSV、Markdown のエクスポートにもディストリ版ヒントを出力します。
- **EOL 判定精度の向上**: 未知のバージョンやサイクルの照合において、古いバージョンが最新サポート中サイクルと誤判定される既定値のバグが是正され、安全に EOL または Unknown と判定されるようになりました。また、解析不能なバージョン表記で誤った不等号判定（バージョン未満）にマッチする問題が解消されました。
- **主要検出ルールの誤検知解消**: Bootstrap クラスのみのページで Tailwind CSS が誤検出される問題、テーマ CSS のみで Font Awesome が誤検出される問題、無関係なスクリプト名（`orgchart.js`, `md3.js` 等）で Chart.js や D3.js が誤検出される問題、Passenger サーバー単独で Ruby on Rails が誤検出される問題が解消されました。
- **ライブラリ検出の拡充**: 利用頻度の高い JavaScript ユーティリティである Lodash および Moment.js が新しく検出対象に追加されました。Underscore.js との誤認防止ガードも備えています。
- **DOM シグナル検出の安定性向上**: ルール定義と連動した DOM セレクタ自動収集機構により、Alpine.js、htmx、Material UI、Spring Security、Ruby on Rails などの DOM マーカーによる技術検出が確実に動作するようになりました。
- **UI 表示のセキュリティ強化（XSS 防止）**: ポップアップおよびダッシュボードにおいて、HTML 要素への値の展開時にエスケープ処理を徹底し、外部リンクの href に `https:` スキームのみを許可する `safeHref` 処理を導入したことで、悪意ある技術情報や URL からの XSS リスクを排除しました。
- **ダッシュボード履歴機能の安定化**: 調査履歴一覧の「表示」「削除」ボタンのインライン `onclick` を全廃し、イベント委譲に移行したことで、MV3 の CSP 規約に準拠し、動作の安定性と安全性を向上させました。

## 6. 指示からの逸脱・判断事項

| 箇所 | 指示 | 実際に行ったこと | 理由 |
| --- | --- | --- | --- |
| T02 | `report.coverage.headers = 'unobserved'` の検証 | `report.coverage.headers = 'partial'` および `details.unobservedPreScan = true` を検証 | 既存の `CoverageStatus` 型定義が `'full' \| 'partial' \| 'none'` であり `'unobserved'` が存在しないため、既存の仕様と型整合性を保つため。 |
| T06 | content-script でルール定義を参照して DOM セレクタを収集 | ビルド時スクリプト `generate-spec-catalog.mjs` で `dom-selectors.generated.ts` を自動生成し、content-script はそれのみを参照 | content-script がルール JSON 等の共有モジュールを import すると Vite が共有チャンクを作成し、MV3 content-script に import 文が含まれて実行不能になる制約（R03/R07）を回避するため。 |
| T08 | `safeHref` による URL の安全性検査 | `safeHref` に加え、安全でないスキームや無効な URL の場合に span 要素（エスケープ済みテキスト）にフォールバックする `renderSafeExternalLink` を新設して共通化 | リンク化できない不正・危険な URL（`javascript:` 等）であっても情報を失わず安全にテキスト表示するため。 |
| T09 | 旧 DB・旧エンジンファイルの削除 | エージェントは、旧 DB・旧エンジンファイルの中身を最小限にし、ソースとテストからの参照を 0 件にした。ファイル自体は、人間がサンドボックスの外で削除した | macOS のサンドボックス（Seatbelt / sandbox-exec）の制約で、エージェントからはファイルを削除できなかった（unlink / rm が EPERM）ため。 |
| T09 | 既存テストの移行（`tests/version-check.test.ts`） | Bootstrap の CVE-2019-8331 を確かめるバージョンを 4.2.0 から 4.3.0 に変更 | 同梱の脆弱性 DB（`advisory-db.json`、NVD 準拠）の範囲が「3.4.1 未満、または 4.3.0 以上 4.3.1 未満」であり、旧 DB の範囲（4.0.0 以上 4.3.1 未満）とは異なるため。GitHub Advisory は 4.0.0〜4.3.0 を対象としており、情報源で範囲が異なる（§10 に申し送り）。 |

## 7. 未解決の問題・既知の制限

- 未解決の問題はない（夜間実行の直後に残っていた T09 のファイル削除と E2E の実行は、人間が対応して解消した）。
- 既知の制限: E2E スモークテストは、テスト用サーバー（`npm run test-server`）を別に起動しておく必要がある（v1.6.5 からの仕様。§10 に申し送り）。
- 既知の制限: 夜間（無人）モードでは、エージェントがサンドボックスの中でファイルを削除できない。ファイルの削除を含むタスクは、スクリプトか人間が仕上げる必要がある（§10 に申し送り）。

## 8. 人間の確認が必要な事項

- [ ] `PRIVACY_POLICY.md` の修正文言の承認（T10 / DOC-08: Cookie 値即時破棄、content script の配置・実行契機、webRequest 許可リストの明記。法的文書のため確認が必要）
- [x] サンドボックス外での旧 DB・旧エンジンファイルの削除（T09 / DOC-09。`git rm -r src/security/cve src/security/eol` を実行し、C05 は PASS）
- [x] E2E スモークテストの実機実行と結果確認（T12。`node scripts/dev/check-v1.6.6.mjs --e2e` で R06 が PASS）
- [ ] ポップアップ・ダッシュボードの目視確認（未観測バッジ、ディストリ版バッジ、外部リンク、履歴の表示・削除操作）

## 9. 変更ファイル一覧

```
 .agents/skills/v166-report/SKILL.md    |  19 +
 .agents/skills/v166-start/SKILL.md     |  16 +
 .agents/skills/v166-task/SKILL.md      |  18 +
 .agents/skills/v166-verify/SKILL.md    |  10 +
 AGENTS.md                              |  79 ++++
 PRIVACY_POLICY.md                      |  28 +-
 README.md                              |   4 +-
 dashboard.html                         |   2 +-
 docs/DETECTION_SPECIFICATION.md        |  27 +-
 docs/MAINTENANCE_GUIDE.md              |  39 +-
 docs/dev/v1.6.6/COMPLETION_REPORT.md   | 165 +++++++++
 docs/dev/v1.6.6/INSTRUCTIONS.md        | 325 ++++++++++++++++
 docs/dev/v1.6.6/README.md              | 206 +++++++++++
 docs/dev/v1.6.6/REPORT_PROMPT.md       |  25 ++
 docs/dev/v1.6.6/REPORT_TEMPLATE.md     |  84 +++++
 docs/dev/v1.6.6/TASK_PROMPT.md         |  29 ++
 docs/dev/v1.6.6/WORKLOG.md             | 291 +++++++++++++++
 docs/dev/v1.6.6/agy-permissions.json   | 219 +++++++++++
 docs/dev/v1.6.6/check-result.json      | 117 ++++++
 package-lock.json                      |   4 +-
 package.json                           |   5 +-
 popup.html                             |   2 +-
 public/manifest.json                   |   2 +-
 scripts/dev/agy-permissions.mjs        | 139 +++++++
 scripts/dev/check-v1.6.6.mjs           | 229 ++++++++++++
 scripts/dev/overnight.sh               | 462 +++++++++++++++++++++++
 scripts/generate-spec-catalog.mjs      |  37 ++
 scripts/test-e2e-smoke.mjs             | 104 +++++-
 src/background/service-worker.ts       | 124 ++++++-
 src/content/content-script.ts          |  65 +++-
 src/content/dom-selectors.generated.ts |  57 +++
 src/dashboard/dashboard.css            |   6 +
 src/dashboard/dashboard.html           |   2 +-
 src/dashboard/dashboard.ts             | 659 ++++++++-------------------------
 src/dashboard/render.ts                | 511 +++++++++++++++++++++++++
 src/detection/advisory.ts              | 138 +++++--
 src/detection/engine.ts                | 130 +++++--
 src/detection/rules/backend.json       |   2 +-
 src/detection/rules/frontend.json      |  52 ++-
 src/detection/rules/index.ts           |   2 +-
 src/detection/rules/language.json      |   4 +-
 src/export/csv.ts                      |   4 +-
 src/export/markdown.ts                 |  16 +-
 src/popup/popup.css                    |   1 +
 src/popup/popup.html                   |   2 +-
 src/popup/popup.ts                     | 306 ++-------------
 src/popup/render.ts                    | 322 ++++++++++++++++
 src/security/cve/cve-database.json     | 256 -------------
 src/security/cve/cve-engine.ts         | 141 -------
 src/security/eol/eol-database.json     | 246 ------------
 src/security/eol/eol-engine.ts         |  87 -----
 src/security/version-matcher.ts        |   3 +-
 src/shared/html.ts                     |  84 +++++
 src/shared/types.ts                    |   4 +
 test-server/server.mjs                 |  48 +++
 tests/advisory.test.ts                 |   9 +
 tests/dashboard-history.test.ts        | 199 ++++++++++
 tests/detection.test.ts                | 277 ++++++++++++++
 tests/export.test.ts                   |  23 ++
 tests/fixtures/dom-signal-fixtures.ts  | 108 ++++++
 tests/review-v1.6.5-acceptance.test.ts |  20 +-
 tests/rule-reachability.test.ts        | 112 ++++++
 tests/service-worker.test.ts           |  82 ++++
 tests/spec-integrity.test.ts           |  36 +-
 tests/ui-escaping.test.ts              | 266 +++++++++++++
 tests/version-check.test.ts            |  47 ++-
 66 files changed, 5445 insertions(+), 1693 deletions(-)
```

## 10. 次回（v1.7.0）への申し送り

- **P1 受け入れテストの対応**: v1.6.6 スコープ外として残置した P1 項目（SPEC-07/SPEC-08: 同一ドメイン Cookie 判定、SPEC-10: インラインスクリプトハッシュ評価、SPEC-12: クエリパラメータ・フラグメント除外）の仕様確定と実装。
- **ディストリビューション版バックポート判定の第 2 段階**: 今回の第 1 段階（Needs Review 化）から進め、OS パッケージのバージョン採番規則（Debian/Ubuntu/RHEL 等のパッチバージョン）とセキュリティ情報を突合する高精度照合エンジンの検討。
- **動的注入（IMPL-08）の移行検討**: content-script を全ページに配置するマニフェスト宣言型から、調査実行時の動的注入（`chrome.scripting.executeScript`）へ移行し、拡張機能の権限とブラウザリソースの最小化を図る。
- **Bootstrap CVE-2019-8331 の影響範囲**: 同梱 DB（NVD 準拠）は「4.3.0 以上 4.3.1 未満」、GitHub Advisory は「4.0.0 以上 4.3.1 未満」で、情報源によって範囲が異なる。どちらに合わせるか（curated で上書きするか）を、脆弱性 DB パイプラインの運用として決める。
- **E2E のテスト用サーバーの自動起動**: `scripts/test-e2e-smoke.mjs` がテスト用サーバーを自動で起動・停止するようにし、`npm run test:e2e` だけで完結させる。
- **夜間モードでのファイル削除**: エージェントがサンドボックスの中でファイルを削除できないため、削除の指示を `.agy-out/result.json` に書かせ、夜間スクリプトがサンドボックスの外で `git rm` する仕組みを追加する。
- **その他の課題**: `docs/MAINTENANCE_GUIDE.md` §2.8 に整理した残課題（末尾ハイフンヘッダーの扱い、data: スキームの完全サニタイズ、パス内機密情報のマスキング等）。
