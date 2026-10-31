# 夜間（無人）モード: 完了報告書の作成

あなたはこのリポジトリの開発担当です。人間は応答しません。質問や確認をせず、最後まで自分で判断して進めてください。リポジトリ直下の `AGENTS.md` のルールと禁止事項は、すべて有効です。

T01〜T12 の作業は終わっています（未完了のものを含む）。`docs/dev/v1.6.6/REPORT_TEMPLATE.md` をもとに、`docs/dev/v1.6.6/COMPLETION_REPORT.md` を作成してください。すべての `<...>` を埋めます。

## 材料（スクリプトがサンドボックスの外で用意したもの）

- `docs/dev/v1.6.6/WORKLOG.md` … 各タスクの記録
- `docs/dev/v1.6.6/check-result.json` … 総合チェック（`node scripts/dev/check-v1.6.6.mjs`）の結果
- `.agy-out/tasks.txt` … タスクごとの結果（コミット済み / 未完了）とコミットの sha
- `.agy-out/git-log.txt` … `git log --oneline main..HEAD`
- `.agy-out/diffstat.txt` … `git diff --stat main...HEAD`
- `.agy-out/test-summary.txt` … `npm test` と `npm run build` の結果
- `.agy-out/env.txt` … OS・Node.js・npm・agy のバージョン

## 書き方のルール

- §1 に「夜間（無人）モードで実施。コーディングは Antigravity CLI、テストとコミットは夜間スクリプト（scripts/dev/overnight.sh）がサンドボックスの外で実行」と書く。
- §4 の数値は `.agy-out/test-summary.txt` と `check-result.json` の値をそのまま使う。E2E（`npm run test:e2e`）は「未実行（夜間モード。人間が確認）」とする。
- `check-result.json` の C11（完了報告書）は、報告書を作る前に実行した結果なので FAIL になっている。報告書には「C11 は本報告書の作成で解消（スクリプトが再チェック）」と書く。
- 未完了・一部完了のタスクは §3 と §7 に、人間に判断してほしいことは §8 に、漏れなく書く。`PRIVACY_POLICY.md` の文言承認（T10）は §8 に必ず載せる。
- 推測で「完了」と書かない。実行していないものは「未実行」と書く。
- `git add` / `git commit` はしない（スクリプトが行う）。
- 作成が終わったら `.agy-out/result.json` に `{"task": "REPORT", "status": "done", "summary": "完了報告書", "ids": "", "note": ""}` を書く。
