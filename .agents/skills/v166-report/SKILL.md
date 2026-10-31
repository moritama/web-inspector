---
name: v166-report
description: v1.6.6 の完了報告書（docs/dev/v1.6.6/COMPLETION_REPORT.md）を作成し、最終チェックの結果を反映してコミットする。
---

# 完了報告書の作成

`docs/dev/v1.6.6/REPORT_TEMPLATE.md` をコピーして `docs/dev/v1.6.6/COMPLETION_REPORT.md` を作成し、すべての `<...>` を埋めてください。

材料:
- `docs/dev/v1.6.6/WORKLOG.md`
- `docs/dev/v1.6.6/check-result.json`（無ければ先に `node scripts/dev/check-v1.6.6.mjs` を実行する）
- `git log --oneline main..HEAD` と `git diff --stat main...HEAD` の出力

ルール:
- 実行していないテストは「未実行」、環境の都合で実行できなかったものは「実行不可（理由）」と書く。推測で「完了」と書かない。
- 指示書から外れた実装・判断は、すべて §6 に書く。
- `PRIVACY_POLICY.md` の変更は §8 に「人間の承認が必要」として必ず載せる。
- 作成後に `node scripts/dev/check-v1.6.6.mjs` を再実行し、その結果で §1 と §4 を更新してから、報告書・check-result.json・WORKLOG.md をコミットする（push はしない）。
