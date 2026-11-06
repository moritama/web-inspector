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
