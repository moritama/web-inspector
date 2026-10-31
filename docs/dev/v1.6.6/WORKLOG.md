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

---

## T03 EOL既定値の是正・解析不能バージョン・実行時値の検証 (2026-10-31 10:42)
- 変更ファイル:
  - `src/detection/advisory.ts`
  - `src/security/version-matcher.ts`
  - `src/background/service-worker.ts`
  - `tests/review-v1.6.5-acceptance.test.ts`
  - `tests/version-check.test.ts`
  - `tests/service-worker.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - `matchEolPolicy()` における照合順序を (1) major.minor 完全一致、(2) major 一致、(3) N.x 形式（majorの数値一致）、(4) N+ 形式の優先順位で走査するように是正し、`1.x` サイクルが `10.2.0` などの誤った major に一致する不具合を解消した。
  - どのサイクルにも一致しない場合、エントリ中の最も古いサイクル（major.minor で比較）より古い場合は `status: 'EOL'`、それ以外は `status: 'Unknown'` と判定するようにし、「先頭エントリが Supported なら Supported」とする危険な既定動作を削除した（SPEC-04）。
  - `matchOfflineAdvisories()` 冒頭で `parseVersionParts(version)` が null となる解析不能バージョン（`custom-build` など）をバージョン不明と同様に `Unknown Version` / `Needs Review` / advisories 空として即座に返すようにした（SPEC-06）。
  - `satisfiesVersionRange()` および `satisfiesSingleClause()` は、解析不能なバージョンに対して常に `false` を返すようにし、`< X` に誤って一致する副作用を防止した（SPEC-06）。
  - MAIN world から取得した実行時バージョンについて、`executeInspection()` の直後に型（string）、長さ（1〜32文字）、正規表現（`/^\d+(\.\d+){0,3}([-+.][0-9A-Za-z.-]{1,16})?$/`）を検証し、満たさない値は null に無害化するようにした。また `frameworkMarkers` は既知のマーカー（`__reactContainer$`, `__vue_app__`）のみを許可リストで残すようにした（IMPL-04）。
  - MAIN world 関数内の `querySelectorAll('div[id], main, ...')` の走査対象を `.slice(0, 200)` で先頭200要素までに制限し、重いページでの負荷を防止した（IMPL-04）。
  - 受け入れテスト `SPEC-04` および `SPEC-06` の skip を解除（期待値は無変更）。`tests/version-check.test.ts` に解析不能バージョンの判定テストおよび `1.x` サイクル非一致テストを追加し、`tests/service-worker.test.ts` に実行時値およびマーカーの無害化テストを追加した。
- 未解決: なし

---

## T04 ディストリ版のバックポート考慮・第1段階 (2026-10-31 10:55)
- 変更ファイル:
  - `src/shared/types.ts`
  - `src/detection/advisory.ts`
  - `src/detection/engine.ts`
  - `src/popup/popup.ts`
  - `src/dashboard/dashboard.ts`
  - `src/export/csv.ts`
  - `src/export/markdown.ts`
  - `tests/review-v1.6.5-acceptance.test.ts`
  - `tests/detection.test.ts`
  - `tests/advisory.test.ts`
  - `tests/export.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - `DetectedTechnology` に任意フィールド `distroHint?: string` を追加した（SPEC-02）。
  - `DetectionEngine` の header シグナル処理において、バージョンを抽出したヘッダー値全文から (1) 括弧内OS名（`/\((Ubuntu|Debian|CentOS|Red Hat(?: Enterprise Linux)?|RHEL|Fedora|AlmaLinux|Rocky Linux|Amazon Linux|SUSE|Raspbian)\)/i`）および (2) パッケージ版接尾辞（`/^[0-9.]+[-~+][0-9A-Za-z.~+-]*(ubuntu|deb\d*|el\d+|amzn\d*|fc\d+)/i`）を検出し、標準的なディストリビューション名（例: 'Ubuntu', 'Debian', 'RHEL', 'Amazon Linux'等）を `distroHint` に設定するようにした。Unixなどの汎用OS名はディストリ扱いせず従来通り照合する。
  - `matchOfflineAdvisories()` に `options?: MatchOfflineAdvisoriesOptions` 引数を追加し、`options.distroHint` が渡された場合は既存の Linux パッケージ分岐と同様に `Needs Review` / `Unknown Version` とし、ディストリビューション名を含むバックポート注記を recommendation および warning に設定するようにした。
  - ポップアップおよびダッシュボードにおいて、`distroHint` を持つ技術に「ディストリ版（バックポートの可能性）」バッジを表示し、詳細モーダルやアコーディオン内でもバックポート考慮の注記を表示するようにした。
  - JSON、CSV、Markdown の各エクスポート機能において `distroHint` を出力するように拡張した（CSVには「ディストリ版ヒント」列を追加、Markdownには検出技術一覧およびライブラリセキュリティ表にディストリ版を出力）。
  - 情報露出（SEC-DISC-01）の判定ロジックは変更せず維持した。
  - 受け入れテスト `SPEC-02` の skip を解除（期待値は無変更）。`tests/detection.test.ts` に `nginx/1.18.0 (Ubuntu)`（Needs Review）、`Apache/2.4.58 (Unix)`（通常照合）、`PHP/8.1.2-1ubuntu2.14`（Needs Review）のテストを追加した。さらに `tests/advisory.test.ts` および `tests/export.test.ts` にも単体テストを追加した。
- 未解決: なし

---

## T05 誤検知する検出ルールの修正 (2026-10-31 11:06)
- 変更ファイル:
  - `src/detection/rules/frontend.json`
  - `src/detection/rules/language.json`
  - `tests/review-v1.6.5-acceptance.test.ts`
  - `tests/detection.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - `tailwind` の css シグナルについて、Bootstrap のクラス（`d-flex justify-content-between` 等）に誤一致する汎用パターンを廃止し、Tailwind 固有のバリアント接頭辞（`sm:`, `md:`, `lg:`, `xl:`, `2xl:`, `hover:`, `focus:`, `dark:` 等）、任意値（`-[...]`）、カラースケール（`-(50|[1-9]00|950)`）に限定した。重みを 80 から 70 に引き下げ、単独で medium、script シグナル等との組み合わせで高確信度（high）になるよう調整した（SPEC-09）。
  - `fontawesome` の link シグナルについて、任意の `all.css` や `small.css` に部分一致していた `all(?:\.min)?\.css` を削除し、`font-?awesome`、`use.fontawesome.com`、`kit.fontawesome.com` を含むアセットに限定した。また、Font Awesome 公式 Kit（`https://kit.fontawesome.com/abc123.js`）の読み込みに対応するため、script シグナル（weight: 85）を追加した（SPEC-09）。
  - `chartjs` の script シグナルについて、`orgchart.js` 等の無関係なライブラリに一致しないようファイル名先頭に `(?:^|/)` アンカーを付与し、さらに CDN 経由のパス形式（`/chart.js@`, `/npm/chart.js`）も許可するようにした（SPEC-09）。
  - `d3` の script シグナルについて、`md3.js` 等に誤一致しないようファイル名先頭に `(?:^|/)` アンカーを付与し、さらに npm/CDN パス（`/d3@[0-9]`）を許可するようにした（SPEC-09）。
  - `ruby-on-rails` の header シグナル（`X-Powered-By: Phusion Passenger`）について、Passenger は Node.js や Python 等も動作させるため単独で Rails と断定できない問題に対し、重みを 80 から 40 に引き下げた（単独では採用閾値 50 未満となり高確信度にならない）（SPEC-09）。
  - 受け入れテスト `SPEC-09`（4件）の `it.skip` を解除（期待値は無変更）。`tests/detection.test.ts` に Bootstrap クラス群からの Tailwind 陰性判定、Tailwind 固有クラスからの陽性判定、テーマ css からの Font Awesome 陰性判定、cdnjs / kit からの Font Awesome 陽性判定、orgchart.js / md3.js の Chart.js / D3.js 陰性判定、正規 D3.js の陽性判定、Passenger 単独での Rails 抑制判定を網羅的に追加した。
- 未解決: なし

---

## T06 DOMシグナル収集の汎用化と到達性テスト (2026-10-31 11:43)
- 変更ファイル:
  - `src/shared/types.ts`
  - `src/content/dom-selectors.generated.ts`
  - `src/content/content-script.ts`
  - `src/detection/engine.ts`
  - `src/detection/rules/backend.json`
  - `src/detection/rules/language.json`
  - `scripts/generate-spec-catalog.mjs`
  - `tests/fixtures/dom-signal-fixtures.ts`
  - `tests/rule-reachability.test.ts`
  - `tests/spec-integrity.test.ts`
  - `tests/review-v1.6.5-acceptance.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - content-script が service-worker と共有モジュール（ルールJSON等）を import すると Vite が共有チャンクを作成して content-script.js に import 文が入る（通常のスクリプトとして読み込まれるため動作不能になる）制約（R03/R07）に対応するため、ルール JSON から DOM セレクタのみを抽出した独立ファイル `src/content/dom-selectors.generated.ts` を作成し、content-script はこれのみを import する設計とした。
  - `scripts/generate-spec-catalog.mjs` に `generateDomSelectorsFile()` を追加し、`npm run spec:generate` 実行時にルール定義からセレクタ一覧が自動更新されるようにした。さらに `tests/spec-integrity.test.ts` に生成ファイルとルール定義の一致を検証するテストを追加した。
  - `content-script.ts` において、生成されたセレクタ群（およびフォールバック用セレクタ）に対して `document.querySelector` を実行し、一致したセレクタを `domMarkers` に自動追加する汎用ロジックを実装した。`ng-version`、`__NEXT_DATA__`、`__NUXT_DATA__` の既存特殊処理を維持しつつ、Rails の `meta[name='csrf-param']` については content 属性値（例: `authenticity_token`）もマーカーに追加するようにした（DOC-01）。
  - Google Tag Manager の `target: "iframe"` シグナル（`googletagmanager.com/ns.html`）について、セレクタ探査で `iframe` 要素が見つかった際に要素自体のセレクタ文字列だけでなく、`src` 属性値も `domMarkers` に収集するよう改修した。また、`noscript` タグ走査において happy-dom 環境で `textContent` が空になる挙動に対応するため、`innerHTML` も含めて走査するよう修正した。
  - Spring Boot の Whitelabel Error Page などテキストで判定するシグナルについて、`backend.json` の `target` を `body` から `h1` に変更し、content-script で見出し要素（`h1`, `h2` 等）の `textContent` 先頭200文字を `elementTexts: string[]`（`DomSignals` に追加）として収集して、`engine.ts` の `case 'dom':` で `elementTexts` を照合する処理を追加した。
  - `tests/fixtures/dom-signal-fixtures.ts` を新規作成し、全26件の `type: 'dom'` シグナルを発火させる最小 HTML フィクスチャを定義した。
  - `tests/rule-reachability.test.ts` を新規作成し、全26件の DOM シグナルに対応するフィクスチャが存在すること、および各フィクスチャを読み込んで `extractDomSignals()` → `DetectionEngine.detect()` することで該当技術が確実に検出されること（到達性）を検証した。なお、Bootstrap（weight: 40）は単独では採用閾値（50）未満で除外される設計のため、エビデンス（`domMarkers` に `.container`）が収集されていることを検証対象とした。また、happy-dom 環境で iframe 要素接続時に発生する page loading 抑制の console.error をテスト実行時に抑制した。
  - 受け入れテスト `tests/review-v1.6.5-acceptance.test.ts` の `DOC-01`（Alpine.js, htmx, Material UI, Spring Security, Ruby on Rails の5件）の `it.skip.each` を `it.each` に解除した（期待値は無変更）。
- 未解決: なし

---

## T07 Lodash / Moment.js ルール追加 (2026-10-31 11:59)
- 変更ファイル:
  - `src/detection/rules/frontend.json`
  - `src/background/service-worker.ts`
  - `tests/review-v1.6.5-acceptance.test.ts`
  - `tests/detection.test.ts`
  - `tests/spec-integrity.test.ts`
- 実行したテスト:
  - `npx tsc --noEmit` → PASS（型エラーなし）
  - `node scripts/dev/check-v1.6.6.mjs --static` → C03 (P0受け入れテスト) PASS, C06 (Lodash/Momentルール) PASS
  - ※無人（夜間）モードのため、vitest/全テストは外側スクリプトが実行
- 判断したこと:
  - `src/detection/rules/frontend.json` に `id: 'lodash'`（Lodash）および `id: 'moment'`（Moment.js）の2ルールを `category: 'js-css-library'` として追加した。
  - スクリプトURL検出シグナル（`type: 'script'`）において、cdnjs（`/lodash.js/<version>/`、`/moment.js/<version>/`）、npm / jsdelivr（`/lodash@<version>`、`/moment@<version>`）、およびファイル名（`lodash.min.js`, `moment-with-locales.min.js`, バージョン付きファイル名）を1つのシグナル定義で網羅する正規表現パターンとバージョン抽出用 `versionRegex` を設計し、URLからの重複エビデンス発生を防止した。
  - `src/background/service-worker.ts` の `fetchRuntimeVersions` において、Underscore.js にも `window._.VERSION` が存在するため、`typeof w._?.cloneDeep === 'function'` かつ `typeof w._?.VERSION === 'string'` の場合のみ `w._.VERSION` を採用し、それ以外（Underscore.js等）は `null` とする誤認防止ガードを実装した（DOC-02）。
  - 受け入れテスト `tests/review-v1.6.5-acceptance.test.ts` の `DOC-02` の `it.skip` を解除した（期待値は無変更）。
  - `tests/detection.test.ts` に cdnjs / jsdelivr / ローカルスクリプトからの Lodash / Moment.js の検出・バージョン抽出テスト、および類似ファイル名（`my-lodash.js`, `momentary.js`）からの誤検出防止テストを追加した。
  - ルール数が68から70に増加したことに伴い、`tests/spec-integrity.test.ts` の登録技術数アサーションを70に更新した（外側スクリプトによる `npm run spec:generate` 実行後のカタログ同期と整合）。
- 未解決: なし
