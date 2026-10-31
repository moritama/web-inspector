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

---

## T02 ヘッダー未観測時の扱い・タブURL照合 (2026-10-31 10:37)
- 変更ファイル:
  - `src/background/service-worker.ts`
  - `src/popup/popup.ts`
  - `src/popup/popup.css`
  - `src/dashboard/dashboard.ts`
  - `src/dashboard/dashboard.css`
  - `tests/review-v1.6.5-acceptance.test.ts`
  - `tests/service-worker.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - `getCachedHeaders()` の戻り値に含まれる `url` の origin と現在のタブ URL の origin が一致しない場合、`headersObserved` を false とし、さらに他オリジンのヘッダーが混入しないよう `responseHeaders` を空オブジェクトとして扱うようにした（IMPL-02）。同一 origin かつパス違いの場合はキャッシュが維持され通常通り診断が行われる。
  - `headersObserved` が false の場合、ヘッダー依存のセキュリティ診断項目（`SEC-HSTS-`, `SEC-CSP-`, `SEC-XFO-`, `SEC-XCTO-`, `SEC-REF-`, `SEC-PERM-`, `SEC-CORS-`, `SEC-DISC-`）を `status: 'unknown'`, `severity: 'info'`, `observed: 'HTTPレスポンスヘッダー未観測'`, `description`/`recommendation` を再読み込み推奨の文言に置き換える処理を追加した。ただし `domSignals.metaCsp` が存在する場合は例外として meta 由来の CSP 判定を維持する（SPEC-01）。
  - `chrome.tabs.onReplaced` リスナーを登録し、プリレンダリングによるタブ切り替え時に `removedTabId` のキャッシュを `addedTabId` に移行（インメモリ Map および `chrome.storage.session` の両方）するようにした（SPEC-16）。
  - ポップアップおよびダッシュボードにて、`status: 'unknown'` の項目が「未観測」バッジ（灰色スタイル）として明瞭に識別できるように UI と CSS を追加した。
  - 受け入れテスト `tests/review-v1.6.5-acceptance.test.ts` の `SPEC-01` の `it.skip` を解除し、`tests/service-worker.test.ts` に origin 不一致時の未観測化および同一 origin・別パス時の観測継続を検証するテストを追加した。なお、1回目のテスト実行失敗（`report.coverage?.headers` の期待値が型に存在しない `'unobserved'` になっていた点）について、既存の `coverage.ts` 仕様に合わせ `headers` は `'partial'`、`details.unobservedPreScan` は `true` を検証するように修正した。
- 未解決: なし


