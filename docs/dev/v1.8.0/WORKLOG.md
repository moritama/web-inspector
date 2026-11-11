# v1.8.0 作業記録

各工程の終わりに、次の形式で追記してください。完了報告書の材料になります。このファイルはコミットされるので、作業者のユーザー名・ローカルパス・ツールの製品名は書かないでください（担当は「設計とテストの担当」「実装の担当」と書く）。

```
## T00 設計  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <指示書に書かれていなかったことをどう決めたか>
- 外部の事実: <事実 — 一次資料の URL（確認日）。無ければ「なし」>
- 未解決: <あれば>

## T00 実装  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <…>
- 未解決: <あれば>
```

---

## T01 設計  (2026-11-11 22:30)
- 変更ファイル（新規）: tests/helpers/release-version.ts, tests/helpers/test-hygiene.ts, tests/setup/advisory-db.ts, tests/test-hygiene.test.ts, tests/release-version.test.ts, tests/advisory-fixture-default.test.ts, docs/dev/v1.8.0/design/T01.md
- 変更ファイル（既存テスト）: tests/spec-integrity.test.ts, tests/advisory-db-invariants.test.ts, tests/advisory.test.ts, tests/security.test.ts, tests/advisory-pipeline.test.mjs
- 期待値を変えた既存テスト（全件。詳細は設計メモ T01「期待値を変えた既存テスト」）:
  - spec-integrity.test.ts「package.json, manifest.json, 各HTML, README のバージョン表記が完全に一致」: manifest との比較を isSameRelease に（判定は同じか、より厳密）
  - spec-integrity.test.ts「v1.7.1 T12: 版の表記が…」: 版を package.json から取る。manifest は isSameRelease。同梱 DB の minExtensionVersion の確認を削除（invariants に移動）。題名を変更
  - advisory-db-invariants.test.ts「schemaVersion が…」: 期待値を build-db の OUTPUT_SCHEMA_VERSION に
  - advisory-db-invariants.test.ts「全 14 製品が…」「全エントリの必須項目…」: 製品の固定リストを catalog.json の products に
  - advisory-db-invariants.test.ts「T05 (P1): …minExtensionVersion が 1.7.0…CVE-2023-25690…」: 削除し、「manifest の版と minExtensionVersion（build-db の MIN_EXTENSION_VERSION と一致）」と「固定 DB で Apache の照合」の 2 件に分割。件数の下限と特定 CVE の確認をやめた
  - advisory.test.ts「D17: getAdvisoryDbMetadata()…」: advisory-db-invariants.test.ts に移し、件数の下限を同梱 DB の値との一致に変更
  - security.test.ts「status が info の項目が…WARN と表示されない」: 入力の extensionVersion を readPackageVersion() に（期待値は不変）
  - advisory-pipeline.test.mjs「classify-release (c)」: 合成の版を 1.7.1 から 1.7.2 に（期待値は不変）
- 判断したこと:
  - 同梱 DB を読んでよい許可リストは advisory-db-invariants.test.ts の 1 件だけ。版の文字列の許可リストは空
  - 「読む」は import／require の指定子・path.join の部品・読み込み系の呼び出しの引数に現れること。パスを配列に書くだけ（changedFiles）は対象外
  - 「版の文字列」は引用符で囲まれた中身が現在の版（v 付き・4 つ目の数字付きを含む）か、正規表現でエスケープした形。題名・コメントの中の言及は対象外
  - setup ファイルは tests/setup/advisory-db.ts に設計とテストの担当が作成。実装の担当は vite.config.ts の test.setupFiles に追加するだけ
  - setup では読み込み時と beforeEach で固定 DB を入れ直す（既存の afterEach で null に戻すテストがあるため）
  - 固定 DB の dataVersion を期待値に書いている既存テスト（export / ui-escaping / advisory）は、同梱 DB に依存しないので変えない
  - setupFiles を入れた状態を一時の設定ファイル（コミットされない作業用の場所）で模擬し、全テストが合格することを確かめた（vite.config.ts の記述を見る 1 件を除く）
- 外部の事実: Vitest の setupFiles は各テストファイルの前に同じプロセスで実行され、パスは root からの相対 — https://vitest.dev/config/setupfiles（2026-11-11）
- 未解決: なし

---

## T01 実装  (2026-11-11 22:35)
- 変更ファイル: vite.config.ts
- 判断したこと:
  - 設計メモの方針に従い、`vite.config.ts` の `test.setupFiles` に `'tests/setup/advisory-db.ts'` を追加した
  - `build` 設定や他の設定は変更せず維持した
- 未解決: なし

---
