---
name: v166-verify
description: v1.6.6 の総合チェック（scripts/dev/check-v1.6.6.mjs）を実行し、FAIL 項目の原因と対応するタスクを示す。修正はしない。
---

# v1.6.6 総合チェック

1. `node scripts/dev/check-v1.6.6.mjs` を実行する。
2. FAIL の項目それぞれについて、原因と、どのタスク（T01〜T12）で直すべきかを示す。
3. 直すのはユーザーが指示してからにする。C11（完了報告書）は報告書の作成前なら FAIL で正常。
