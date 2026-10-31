# AGENTS.md — Web Technology & Security Inspector

このファイルは Antigravity CLI（`agy`）などの AI エージェントがこのリポジトリで作業するときの常設ルールです。毎回の指示より優先度は低いですが、**禁止事項は常に守ってください**。

## プロジェクト概要

- Chrome / Edge 向け拡張機能（Manifest V3, TypeScript, Vite）。閲覧中ページの使用技術を検出し、外部から確認できるセキュリティ設定を**受動的に**診断する。
- 設計原則: 受動的調査のみ（追加リクエストを送らない）／外部送信ゼロ／判定根拠（エビデンス）を必ず保持・表示／断定できないものは断定しない（Needs Review・未観測として扱う）。
- 主要ディレクトリ:
  - `src/background/service-worker.ts` … ヘッダー収集（webRequest）、Cookie 取得、調査の統括（`executeInspection`）
  - `src/content/content-script.ts` … DOM シグナル収集（`extractDomSignals`）
  - `src/detection/` … 技術検出エンジン、ルール JSON（`rules/*.json`）、オフライン脆弱性照合（`advisory.ts`）
  - `src/security/` … ヘッダー・CSP・Cookie・HTTPS 診断
  - `src/popup/`, `src/dashboard/` … UI（ルート直下の `popup.html` / `dashboard.html` がビルドの入口）
  - `scripts/advisories/`, `data/advisories/` … 脆弱性DB 自動更新パイプライン（**変更禁止**）
  - `tests/` … Vitest（`tests/review-v1.6.5-acceptance.test.ts` はレビュー指摘の受け入れテスト）

## 現在の作業

- v1.6.6 開発。手順は **`docs/dev/v1.6.6/INSTRUCTIONS.md`** に従う（タスク T01〜T12）。作業開始時に必ず全文を読むこと。
- 背景となる指摘は `docs/REVIEW_v1.6.5.md`（指摘ID: SPEC / DOC / IMPL）。

## 夜間（無人）モード

`TASK_PROMPT.md` / `REPORT_PROMPT.md` で起動された場合は、人間は応答しない。確認や質問をせず、`INSTRUCTIONS.md` §1「夜間（無人）モードでの追加ルール」に従う。夜間モードでは、エージェントはサンドボックスの中でファイルの編集だけを行い、**コミットとテストの実行はスクリプトが行う**（エージェントは `git commit` / `npm test` を実行しない）。E2E は実行しない。

## コマンド

| 目的 | コマンド |
| --- | --- |
| 依存インストール | `npm ci` |
| 型検査 | `npm run typecheck` |
| 全テスト（型検査＋リンク検査＋Vitest） | `npm test` |
| 単一テスト | `npx vitest run tests/<file>` |
| ビルド | `npm run build`（出力: `dist/`） |
| 検出仕様書カタログの再生成 | `npm run spec:generate`（ルール JSON を変えたら必ず実行） |
| 脆弱性DB 検証 | `npm run advisories:validate` / `npm run advisories:verify-nvd` |
| E2E（Chrome 実機） | `npm run test:e2e`（画面がなければ `xvfb-run -a npm run test:e2e`） |
| v1.6.6 総合チェック | `node scripts/dev/check-v1.6.6.mjs` |

## 作業ルール

- ブランチ `feature/v1.6.6` で作業する。main に直接コミットしない。
- 1 タスク = 1 コミット以上。コミットメッセージは `[T03] EOL既定値の是正 (SPEC-04)` の形式。
- コミット前に必ず `npm test` を実行し、緑であることを確認する。
- 受け入れテストは `it.skip` を外すだけにし、**期待値を書き換えない**。
- 既存テストの削除・期待値の緩和をしない（指示書で明示された移行を除く）。
- 依存パッケージを追加しない。指示にないリファクタリングをしない。
- 不明点・仕様の矛盾に気づいたら、推測で埋めずに `docs/dev/v1.6.6/WORKLOG.md` に記録し、安全側（断定しない・警告を増やさない）の実装にする。
- 作業の節目ごとに `docs/dev/v1.6.6/WORKLOG.md` へ追記する（変更ファイル・実行したテストと結果・判断）。

## コーディング規約

- TypeScript strict。インデント 2 スペース、シングルクォート、セミコロンあり（既存コードに合わせる）。
- ユーザー向け文言は日本語（です・ます調）。コード中のコメントも日本語でよい。
- innerHTML に値を入れるときは必ず `escapeHtml()` を通す。URL を href に入れるときは `safeHref()`（https のみ許可）を通す。インラインイベントハンドラ（`onclick=` 等）は使わない（MV3 の CSP でブロックされる）。
- MAIN world（ページ側）から取得した値は信頼しない。型・長さ・書式を検証してから使う。
- 新しい型フィールドは任意（`?`）で追加し、過去に保存された履歴データを壊さない。
- ルール JSON の正規表現を追加・変更したら、陽性と陰性の両方のテストを付ける。

## 禁止事項（例外なし）

権限設定（`docs/dev/v1.6.6/agy-permissions.json`）とサンドボックスで多くは機械的に拒否されますが、拒否されなくても行わないでください。拒否された操作は、別のコマンドや書き方で回避しようとしないでください。

- `git push`、タグの作成、GitHub Release の作成、Chrome Web Store へのアップロードや提出。
- `src/detection/advisory-db.json` の手編集。
- `data/advisories/**`、`scripts/advisories/**`、`.github/workflows/**`、`scripts/cws-publish.mjs` の変更。
- `npm run advisories:fetch` / `npm run advisories:sync` の実行（外部 API にアクセスするため）。
- 外部サイトへのアクセスを伴うコードの追加（拡張機能は外部送信ゼロが原則）。
- API キーなどの秘密情報をファイル・ログ・コミットに含めること。
- `docs/REVIEW_v1.6.5.md` の編集。
- 作業キット（`AGENTS.md`、`.agents/`、`scripts/dev/`、`docs/dev/v1.6.6/` の INSTRUCTIONS.md・TASK_PROMPT.md・REPORT_PROMPT.md・README.md・REPORT_TEMPLATE.md・agy-permissions.json）の変更。
- `git config` の変更、ブランチの切り替え・削除、`git reset`、`git commit --amend`（履歴の書き換え）。

## 完了の定義

- `docs/dev/v1.6.6/INSTRUCTIONS.md` の各タスクの完了条件を満たしている。
- `node scripts/dev/check-v1.6.6.mjs` がすべて PASS。
- `docs/dev/v1.6.6/COMPLETION_REPORT.md` を作成済み。実行していないテストは「未実行」と正直に書く。
