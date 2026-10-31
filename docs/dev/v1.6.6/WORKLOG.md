# v1.6.6 作業記録（エージェントが追記する）

各タスクの完了時に、次の形式で追記してください。完了報告書の材料になります。

```
## T00 <タスク名>  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 実行したテスト: <command> → <passed/skipped/failed>
- 判断したこと: <指示書に書かれていなかったことをどう決めたか>
- 未解決: <あれば>
```

---

## T01 履歴ボタンのインライン onclick 廃止 (2026-10-31 10:08)
- 変更ファイル:
  - `src/dashboard/dashboard.ts`
  - `src/dashboard/render.ts`
  - `tests/dashboard-history.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - `node scripts/dev/check-v1.6.6.mjs` → C02（インラインイベントハンドラ検査）PASS
- 判断したこと:
  - 履歴一覧のHTML文字列生成処理を純粋関数 `renderHistoryListHtml` として `src/dashboard/render.ts` に切り出し、単体テストを可能にした（T08の描画切り出し方針とも整合）。
  - `historyListContainerEl` に対して `setupActions` 内でイベント委譲（`closest('button[data-id]')`）を設定し、`history-view-btn` で `viewReport`、`history-delete-btn` で `deleteReport` を呼び出すように変更。二重登録を防ぐため `dataset.listenerAttached` でガード。
  - グローバルに公開されていた `(window as any).viewReport` および `(window as any).deleteReport` を削除し、モジュール内関数に変更した。
  - `dashboard.ts` の初期化処理を `initDashboard()` として export し、DOM要素参照も初期化時に最新ノードを取得するようにして、テスト実行時やSPA的更新時の信頼性を向上させた。
  - `tests/dashboard-history.test.ts` を新規作成し、HTML出力に `onclick=` が含まれないこと、XSSエスケープ処理（属性脱出の防止）、クリック時のメッセージ送信（`DELETE_HISTORY_ITEM`）およびキャンセル処理、ビュー遷移を網羅的に検証した。
- 未解決: なし

