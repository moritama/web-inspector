# v1.6.6 改修指示書（Antigravity CLI 向け）

- 対象: Web Technology & Security Inspector v1.6.5 → **v1.6.6**
- 根拠: [レビュー結果・開発指示書](../../REVIEW_v1.6.5.md) 第6章「P0：v1.6.6」
- 作業者: Antigravity CLI（`agy`）（コーディング → 自動テスト → 完了報告書作成まで）
- 人間の担当範囲: 本書 §8 のみ（目視確認・プライバシーポリシー文言の承認・ストア提出）

---

## 0. 前提条件（作業開始前に確認し、満たされていなければ作業せず報告する）

1. 作業ブランチ `feature/v1.6.6` 上にいる（`git branch --show-current`）。main に直接コミットしない。
2. レビューパッチ（`scripts/advisories/`、`tests/review-v1.6.5-acceptance.test.ts`、`docs/REVIEW_v1.6.5.md` など）が取り込み済みである。
3. Node.js 22 以上（`node -v`）。`npm ci` が成功する。
4. ベースライン: `npm test` が「216 passed / 24 skipped」前後で成功し、`npm run build` が成功する。数値が大きく異なる場合は作業前に報告する。

## 1. 進め方のルール

- タスクは §3 の順番（T01 → T12）で 1 つずつ行う。**1 タスク = 1 コミット以上**。コミットメッセージ先頭に `[T03]` のようにタスクIDを付ける。
- 各タスクの最後に必ず `npm test` を実行し、緑であることを確認してからコミットする。赤のままコミットしない。
- 受け入れテスト `tests/review-v1.6.5-acceptance.test.ts` の該当 `describe` の `it.skip` / `it.skip.each` を `it` / `it.each` に変えることが完了条件の一部。**期待値（expect の中身）は変更しない**。期待値が仕様として誤っていると判断した場合は変更せず、報告書の「指示からの逸脱・判断事項」に理由を書いて次へ進む。
- 指示に無い機能追加・リファクタリング・依存パッケージの追加をしない（必要と判断した場合は報告書に提案として書く）。
- 1 つのタスクで 3 回続けて同じテストが直らない場合は、そのタスクを「未完了」として記録し、次のタスクへ進む。
- 作業記録: 各タスク完了時に `docs/dev/v1.6.6/WORKLOG.md` に「タスクID / 変更ファイル / 実行したテストと結果 / 判断したこと」を追記する（報告書の材料）。

### 夜間（無人）モードでの追加ルール

`scripts/dev/overnight.sh` から起動された場合（プロンプトが `TASK_PROMPT.md` / `REPORT_PROMPT.md` の場合）は、人間が応答しない。夜間モードでは、エージェントとスクリプトが次のように分担する。

- **エージェント（サンドボックスの中）**: 1回の実行で1タスクだけ、ファイルを編集する。WORKLOG に記録し、最後に `.agy-out/result.json` を書く。`git add` / `git commit`、`npm test` / `npm run build` / `vitest`、`npm run spec:generate` は実行しない（サンドボックスの中では `.git` に書き込めず、テストも動かないため）。
- **スクリプト（サンドボックスの外）**: エージェントの実行が終わるたびに `npm run spec:generate && npm test` を実行し、通ればコミットする。落ちたら失敗の内容を `.agy-out/test-failure.txt` に書き、次の実行でエージェントに直させる（最大3回）。それでも直らなければ、変更を元に戻して「未完了」と記録する。変更禁止のファイルへの変更は、コミット前に元に戻す。完了報告書の材料（総合チェックの結果など）も用意する。

そのうえで、本書を次のとおりに読み替える。

- 「各タスクの最後に `npm test` を実行し、コミットする」は、スクリプトが行う。エージェントは、テストが通るように実装することに集中する。
- 本書で「止まって報告する」「人間の指示を待つ」としている箇所は、**止まらずに WORKLOG と `result.json` の `note` に記録して終える**（`status` を `partial` / `incomplete` にする）。
- E2E（`npm run test:e2e`）は実行しない。報告書では「未実行（夜間モード）」とする。
- push はしない（権限設定で拒否される。実行中は push 先も無効になっている）。push は、人間が完了報告書を確認した後に行う。
- 権限設定で拒否されたコマンドは、再試行したり別の書き方で回避したりしない。
- **リポジトリの外のファイルを読み書きしない。Web にアクセスしない。** 無人モードではこれらの確認ができず、実行全体がその場で中断する。
- コマンドは `cd` を付けずにリポジトリ直下でそのまま実行する。`bash -c` / `sh -c` / `env` / `xargs` / `git -C` は拒否される。ファイルの作成・編集はシェルのリダイレクトではなく、ファイル編集ツールで行う。

## 2. 禁止事項（AGENTS.md にも記載）

- `git push`、タグ作成、GitHub Release 作成、Chrome Web Store へのアップロード・提出。
- `src/detection/advisory-db.json` の手編集（DB はパイプラインが生成する。T09 でも触らない）。
- `data/advisories/**`、`scripts/advisories/**`、`.github/workflows/**`、`scripts/cws-publish.mjs` の変更（本書で明示した場合を除く）。
- `npm run advisories:fetch` / `advisories:sync` の実行（外部 API へアクセスするため）。
- 秘密情報（API キー等）をファイルやログに書くこと。
- 既存テストの削除・期待値の緩和（T09 で明示したテスト移行を除く）。

---

## 3. タスク一覧

| ID | 指摘ID | 内容 | 主な対象 | 解除する受け入れテスト |
| --- | --- | --- | --- | --- |
| T01 | IMPL-01 | 履歴ボタンのインライン onclick を廃止 | `src/dashboard/dashboard.ts` | （新規テスト） |
| T02 | SPEC-01, IMPL-02, SPEC-16 | ヘッダー未観測時は「未観測」扱い・タブURL照合 | `src/background/service-worker.ts`, popup/dashboard 表示 | SPEC-01 |
| T03 | SPEC-04, SPEC-06, IMPL-04 | EOL既定値の是正・解析不能バージョン・実行時値の検証 | `src/detection/advisory.ts`, `src/security/version-matcher.ts`, SW | SPEC-04, SPEC-06 |
| T04 | SPEC-02 | ディストリ版のバックポート考慮（第1段階） | `src/detection/engine.ts`, `advisory.ts`, rules | SPEC-02 |
| T05 | SPEC-09 | 誤検知する検出ルールの修正 | `src/detection/rules/*.json` | SPEC-09 |
| T06 | DOC-01 | DOMシグナル収集の汎用化と到達性テスト | `src/content/content-script.ts`, rules | DOC-01 |
| T07 | DOC-02 | Lodash / Moment.js ルール追加 | `rules/frontend.json`, SW の実行時取得 | DOC-02 |
| T08 | IMPL-03 | innerHTML への未エスケープ出力の解消 | popup / dashboard | （新規テスト） |
| T09 | DOC-09 | 旧DB（cve-database / eol-database）と旧エンジンの削除 | `src/security/cve/`, `src/security/eol/` | — |
| T10 | DOC-08 | プライバシーポリシーの記述を実装に合わせる | `PRIVACY_POLICY.md` | — |
| T11 | — | バージョン 1.6.6 への更新・ドキュメント整合 | manifest ほか | — |
| T12 | — | E2E 追加・最終確認・完了報告書 | `scripts/test-e2e-smoke.mjs`, `test-server/` | — |

P1 以降（SPEC-03/07/08/10〜16 の残り、DOC-03〜07・10〜12、IMPL-05〜12、NVD 自動取込の有効化）は**今回の対象外**。受け入れテストの SPEC-07/08・SPEC-10・SPEC-12 は skip のまま残す。

---

## 4. 各タスクの詳細

### T01 履歴ボタンのインライン onclick 廃止（IMPL-01）

**背景**: `renderHistoryList()` が `onclick="window.viewReport('...')"` を出力している。MV3 拡張ページの既定 CSP（`script-src 'self'`）でインラインハンドラはブロックされ、「表示」「削除」が動作しない（Chromium で確認済み）。

**変更内容**
1. ボタンを `<button class="... history-view-btn" data-id="${escapeHtml(r.id)}">` / `history-delete-btn` に変える。
2. `historyListContainerEl` に 1 つだけクリックリスナーを登録し（イベント委譲）、`closest('button[data-id]')` で処理を分岐する。リスナーの二重登録を防ぐため、登録は初期化時に 1 回だけ行う。
3. `(window as any).viewReport` / `deleteReport` のグローバル公開を削除し、モジュール内関数にする。
4. `src/` 全体で `on[a-z]+=` 形式のインラインハンドラが残っていないことを確認する（`grep -rnE "\bon(click|change|input|submit|load|error)\s*=" src`）。

**テスト**
- `tests/dashboard-history.test.ts`（happy-dom）を新規作成: `dashboard.html` 相当の要素を用意し、`chrome.runtime.sendMessage` をモックしてダッシュボードを初期化、履歴ボタンのクリックで `DELETE_HISTORY_ITEM` が送信されること、出力 HTML に `onclick=` が含まれないことを検証する。モジュールの初期化が重く単体テストが困難な場合は、`renderHistoryList` を `src/dashboard/render.ts` に純粋関数（文字列を返す）として切り出し、その出力を検証する方法でもよい。
- T12 の E2E でもクリック動作を確認する。

**完了条件**: 上記テストが緑。`scripts/dev/check-v1.6.6.mjs` のインラインハンドラ検査が PASS。

---

### T02 ヘッダー未観測時の扱い（SPEC-01, IMPL-02, SPEC-16）

**背景**: ヘッダーを取得できなかったタブ（拡張導入前から開いていたタブ、SW 起動直後のナビゲーション等）でも、HSTS・CSP・XFO 等を「未設定」と警告し、要確認件数とバッジに加算している。

**変更内容**
1. `executeInspection()` で `headersObserved` が false の場合、ヘッダーに依存するチェック（`checkId` が `SEC-HSTS-`, `SEC-CSP-`, `SEC-XFO-`, `SEC-XCTO-`, `SEC-REF-`, `SEC-PERM-`, `SEC-CORS-`, `SEC-DISC-` で始まるもの）を次のように置き換える。
   - `status: 'unknown'`, `severity: 'info'`
   - `observed: 'HTTPレスポンスヘッダー未観測'`
   - `description`: 「拡張機能がこのページのレスポンスヘッダーを観測できませんでした。ページを再読み込みしてから再調査してください。」
   - `recommendation`: 「ページを再読み込み（リロード）してから再調査してください。」
   - 例外: meta CSP（`domSignals.metaCsp`）が存在する場合の CSP 解析結果は、meta 由来として維持してよい（ただし frame-ancestors 等 meta で無効なものの扱いは既存ロジックに従う）。
2. `requiresAttentionCount` は既に `warning`/`fail` のみ数えているので、上記により自動的に除外されることを確認する。`securityFindings`（重大度別件数）も `unknown`/`info` の扱いが正しいか確認する。
3. **URL 照合（IMPL-02）**: `getCachedHeaders()` が返したエントリの `url` の **origin** が、現在のタブ URL の origin と一致しない場合は「未観測」として扱う（`headersObserved=false`）。SPA の pushState によるパス変化で未観測にしないため、比較は origin のみとする。
4. **プリレンダー（SPEC-16）**: `chrome.tabs.onReplaced` を購読し、`removedTabId` のキャッシュを `addedTabId` へ移す（メモリと `chrome.storage.session` の両方）。
5. ポップアップ・ダッシュボードで `status: 'unknown'` の項目が「未観測」と分かる表示（灰色バッジ等）になっていることを確認し、なっていなければ追加する。既存の「HTTPヘッダー未取得」バナーは残す。

**テスト**
- 受け入れテスト `SPEC-01` の skip を外す。
- `tests/service-worker.test.ts` に追加: (a) キャッシュの origin がタブと異なる場合に未観測扱いになる、(b) 同一 origin・別パスでは観測済みのまま。

---

### T03 EOL 既定値の是正・解析不能バージョン・実行時値の検証（SPEC-04, SPEC-06, IMPL-04）

**変更内容（advisory.ts の `matchEolPolicy`）**
1. 照合順序を次のとおりにする。
   1. `cycle === "major.minor"` の完全一致
   2. `cycle === "major"` の一致
   3. `"N.x"` 形式は **major の数値一致**で判定する（現行の `startsWith` は `1.x` が `10` に一致する誤りがある）
   4. `"N+"` 形式は現行どおり
2. どれにも一致しない場合:
   - 検出バージョンが、エントリ中で最も古いサイクルより古い（major.minor で比較）なら `status: 'EOL'`, `eolDate: null`, recommendation「公式のサポート表に掲載されていない古い系列です。サポート終了（EOL）とみなし、現行系列への移行を推奨します。」
   - それ以外は `status: 'Unknown'`。
   - **「先頭エントリが Supported なら Supported」という既定動作は削除する。**

**変更内容（解析不能バージョン: SPEC-06）**
3. `matchOfflineAdvisories()` の冒頭で、`parseVersionParts(version)` が `null` になる値は「バージョン不明」と同じ結果（`matchStatus: 'Needs Review'`, `offlineMatchStatus: 'Unknown Version'`, advisories 空）を返す。
4. `satisfiesVersionRange()` は、解析できないバージョンに対して常に `false` を返す（`compareVersions` が null を -1 扱いする副作用で `< X` に一致しないようにする）。

**変更内容（実行時値の検証: IMPL-04）**
5. `fetchRuntimeVersions()` の戻り値を `executeInspection()` で受け取った直後に検証する（MAIN world の値はページが自由に偽装できるため）。
   - 採用条件: `typeof === 'string'` かつ 長さ 1〜32 かつ `/^\d+(\.\d+){0,3}([-+.][0-9A-Za-z.-]{1,16})?$/` に一致。満たさない値は `null` にする。
   - `frameworkMarkers` は既知の値（`'__reactContainer$'`, `'__vue_app__'`）のみ残す。
6. MAIN world 関数内の `document.querySelectorAll('div[id], main, ...')` の走査は先頭 200 要素までに制限する。

**テスト**
- 受け入れテスト `SPEC-04`, `SPEC-06` の skip を外す。
- `tests/version-check.test.ts` に追加: `satisfiesVersionRange('abc', '< 3.0.0') === false`、`'1.x'` サイクルが `10.2.0` に一致しないこと。
- 既存テストで「Supported」を期待しているもの（例: 最新系列）が引き続き緑であること。

---

### T04 ディストリ版のバックポート考慮・第1段階（SPEC-02）

**背景**: `versionRegex` が数字部分のみを取り出すため、`Apache/2.4.41 (Ubuntu)` の `(Ubuntu)` や `PHP/7.4.3-4ubuntu2.19` の `-4ubuntu2.19` が失われ、`isLinuxPackageVersion()` が一度も真にならない。

**変更内容**
1. `DetectedTechnology` に任意フィールド `distroHint?: string`（例: `'Ubuntu'`, `'Debian'`, `'RHEL'`, `'ubuntu-package'`）を追加する（`src/shared/types.ts`）。
2. `engine.ts` の header シグナル処理で、バージョンを抽出したヘッダー値の**全文**から次を判定し、`distroHint` を設定する。
   - 括弧内 OS 名: `/\((Ubuntu|Debian|CentOS|Red Hat(?: Enterprise Linux)?|RHEL|Fedora|AlmaLinux|Rocky Linux|Amazon Linux|SUSE|Raspbian)\)/i`
   - パッケージ版の接尾辞（抽出バージョンの直後に続く部分）: `/^[0-9.]+[-~+][0-9A-Za-z.~+-]*(ubuntu|deb\d*|el\d+|amzn\d*|fc\d+)/i`
3. `matchOfflineAdvisories(technology, version, dbOverride?, options?)` に `options.distroHint` を追加し、値がある場合は既存の Linux パッケージ分岐と同じ結果（`Needs Review` / `Unknown Version` + バックポート注記）を返す。注記文: 「{distro} のディストリビューション版です。セキュリティ修正がバックポートされている可能性があるため、バージョン番号だけでは脆弱性の有無を断定できません。ディストリビューションのセキュリティ情報で確認してください。」
4. ポップアップとダッシュボードで、`distroHint` がある技術に「ディストリ版（バックポートの可能性）」バッジを表示する。Markdown / CSV / JSON エクスポートにも `distroHint` を出力する。
5. **情報露出（SEC-DISC-01）の判定は変えない**（バージョンが見えていること自体は引き続き指摘する）。

**テスト**
- 受け入れテスト `SPEC-02` の skip を外す。
- `tests/detection.test.ts` に追加: `nginx/1.18.0 (Ubuntu)` → Needs Review、`Apache/2.4.58 (Unix)` → 従来どおり照合される（`Unix` はディストリ扱いしない）、`PHP/8.1.2-1ubuntu2.14` → Needs Review。

---

### T05 誤検知する検出ルールの修正（SPEC-09）

対象と修正方針（正規表現は例。同等以上に厳密であれば別の書き方でよい）:

| ルール | 現状の問題 | 修正方針 |
| --- | --- | --- |
| `tailwind` の css シグナル | `d-flex justify-content-between`（Bootstrap）に一致し確信度 80 | Tailwind 固有のトークン（`sm:` `md:` `lg:` `xl:` `2xl:` `hover:` `focus:` `dark:` のバリアント接頭辞、`-[...]` の任意値、`text-gray-500` 等のカラースケール `-(50\|[1-9]00\|950)`）に限定する。重みは 70 以下にし、script/link シグナルと合わせて高確信度になる設計にする |
| `fontawesome` の link シグナル | `all(?:\.min)?\.css` が `small.css` や任意の `all.css` に一致 | `font-?awesome` を含むパス、`/fontawesome(-free)?/` 配下の css、`use.fontawesome.com`、`kit.fontawesome.com` に限定する |
| `chartjs` | `orgchart.js` 等に一致 | ファイル名の先頭に `(^\|/)` アンカーを付ける。`/chart.js@`、`/npm/chart.js` も許可 |
| `d3` | `md3.js` 等に一致 | 同様に `(^\|/)d3(\.v\d+)?(\.min)?\.js` と `/d3@\d` |
| `ruby-on-rails` の header シグナル | `X-Powered-By: Phusion Passenger` 単独で 80（Passenger は Node/Python も動かす） | 重みを 45 以下にする（単独では採用閾値 50 未満） |

**テスト**
- 受け入れテスト `SPEC-09` の skip を外す。
- `tests/detection.test.ts` に陽性・陰性を追加する。
  - Bootstrap（陰性・Tailwind が出ないこと）: `d-flex justify-content-between align-items-center` / `container-fluid py-4` / `col-md-6 mb-3 text-muted` / `btn btn-primary px-4`
  - Tailwind（陽性）: `flex items-center justify-between bg-gray-100 px-4 md:px-8` と `text-slate-700 hover:text-slate-900`
  - Font Awesome（陽性）: `https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css`、`https://kit.fontawesome.com/abc123.js` 相当
- 既存の陽性テスト（React, Next.js, WordPress 等）が引き続き緑であること。
- 修正後に `npm run spec:generate` を実行し、`docs/DETECTION_SPECIFICATION.md` のカタログを更新する（`tests/spec-integrity.test.ts` が緑になること）。

---

### T06 DOM シグナル収集の汎用化と到達性テスト（DOC-01）

**背景**: 仕様書に記載された DOM シグナルのうち、Alpine.js `[x-data]`、htmx `[hx-get]`、Material UI `[class*='MuiButton-']`、Font Awesome `i[class*='fa-']`、Spring Security `input[name='_csrf']`、Rails `meta[name='csrf-param']`、Spring Boot の Whitelabel Error Page は、content-script が収集していないため一度も発火しない。

**変更内容**
1. content-script の DOM マーカー収集を、ルール定義の `type: 'dom'` シグナルの `target` から**自動的に**組み立てる方式にする。
   - `target` をカンマで分割した各セレクタについて `document.querySelector()` を試し（例外は握りつぶす）、一致したらそのセレクタ文字列を `domMarkers` に追加する。
   - 既存の特殊処理（`ng-version` の値付きマーカー、`__NEXT_DATA__` 等）は維持する。
   - **重要（ビルド上の制約）**: manifest の `content_scripts` は ES モジュールではなく通常のスクリプトとして読み込まれる。content-script が service-worker と同じモジュール（`src/detection/rules` など）を import すると、Vite が共有チャンクに分割し、`dist/content/content-script.js` の先頭に `import` 文が入って**content-script が動かなくなる**。そのため、ルール JSON を直接 import せず、`dom` セレクタだけを抜き出した生成ファイル `src/content/dom-selectors.generated.ts`（content-script 専用、他から import しない）を作り、それを import する。生成は `scripts/generate-spec-catalog.mjs` に処理を追加し、`npm run spec:generate` で更新されるようにする。生成ファイルとルールの一致を確かめるテストも追加する。
   - ビルド後に `dist/content/content-script.js` に `import` / `export` 文が無く、サイズが 40KB 以下であることを確認する（check スクリプトの R03・R07）。
2. テキストで判定するシグナル（Spring Boot の Whitelabel Error Page）は、`target` を `h1` 等の具体的な要素に変え、content-script が該当要素の `textContent` 先頭 200 文字を `htmlSnippets` とは別のフィールド（例: `elementTexts: string[]`、`DomSignals` 型に追加）で返し、engine の `dom` 処理で照合する。
3. Rails の `meta[name='csrf-param']` シグナルは、マーカー文字列と `pattern`（`authenticity_token`）が一致しないため、`pattern` を `csrf-param` に変えるか、content-script が `meta[name='csrf-param']` の `content` 値をマーカーに含めるようにする。
4. 追加したマーカーで Bootstrap 等の既存判定が変わらないことを確認する。

**テスト**
- 受け入れテスト `DOC-01` の skip を外す。
- **到達性テスト** `tests/rule-reachability.test.ts` を新規作成する。
  - `tests/fixtures/dom-signal-fixtures.ts` に「ルールID → その dom シグナルを発火させる最小 HTML」を定義する。
  - テストは `ALL_TECHNOLOGY_RULES` の **すべての `type: 'dom'` シグナル** について、対応するフィクスチャが存在すること、そのフィクスチャを happy-dom に読み込んで `extractDomSignals()` → `DetectionEngine.detect()` した結果に、そのルールの技術が含まれることを検証する（フィクスチャ未定義のシグナルがあればテスト失敗）。
  - 確信度 50 未満で結果から除外される弱いシグナル（例: Bootstrap `.container` 40）は「エビデンスとして収集されること」を検証対象とする（`detect` の内部結果を直接見られない場合は、そのシグナル単独で除外されることを明示的に許可リストに入れる）。

---

### T07 Lodash / Moment.js ルール追加（DOC-02）

**変更内容**
1. `src/detection/rules/frontend.json` に 2 ルールを追加する。`id` は **`lodash`** と **`moment`**（engine.ts の実行時バージョン処理が `rule.id` で分岐しているため）、`name` は `Lodash` と `Moment.js`、`category` は `js-css-library`。
   - script シグナル例: Lodash `(^|/)lodash(\.core)?(\.min)?\.js`、`/lodash@(\d[\d.]*)`、`/lodash\.js/(\d[\d.]*)/`（cdnjs）。Moment `(^|/)moment(-with-locales)?(\.min)?\.js`、`/moment@(\d[\d.]*)`、`/moment\.js/(\d[\d.]*)/`。バージョンを取れるものは `versionRegex` を付ける。
2. **Underscore.js との誤認防止**: `window._.VERSION` は Underscore にもあるため、`fetchRuntimeVersions()` の lodash 判定を「`typeof w._?.cloneDeep === 'function'` かつ `typeof w._?.VERSION === 'string'`」に変更する。
3. `npm run spec:generate` でカタログを更新する。

**テスト**
- 受け入れテスト `DOC-02` の skip を外す（Lodash の CVE 照合まで検証される）。
- `tests/detection.test.ts` に script URL からの検出（cdnjs / jsdelivr）を追加する。
- 注意: Moment.js の脆弱性照合は、DB 自動更新の初回 PR（`moment` 製品を含む schema 2.2 の DB）がマージされるまでデータがない。Moment の CVE 照合をテストで要求しない。

---

### T08 innerHTML への未エスケープ出力の解消（IMPL-03）

**背景**: DB 由来の値が未エスケープで innerHTML に出力されている。DB を上流から自動取得するようになると、第三者が値を制御できる経路になる（パイプライン側でも無害化済みだが多層防御として必須）。

**変更内容**
1. `escapeHtml` を `src/shared/html.ts` に移し、popup / dashboard の重複定義を置き換える。引数が文字列以外でも `String()` で変換し、`null`/`undefined` は空文字にする。
2. 同ファイルに `safeHref(url: unknown): string | null` を作る。`https:` のみ許可し、それ以外（`javascript:`, `data:`, `http:` 等）と解析不能な値は `null`。`null` の場合はリンクではなくテキストとして表示する。
3. 次の箇所（v1.6.5 時点の目安）を修正する。行番号はずれている可能性があるので、関数名と内容で探すこと。
   - `popup.ts`: 調査エラーの `${message}`、EOL 出典 `eol.sourceUrl`、アドバイザリ参照 `adv.referenceUrls[0]`、`tech.website`、セキュリティ詳細の `check.referenceUrls`
   - `dashboard.ts`: `t.website`、`adv.title`、`c.referenceUrls`（href と表示テキストの両方）、許容設定取得失敗時の `${err}`
   - 上記以外にも、`${...}` のうち数値・固定文字列・既にエスケープ済み以外のものが innerHTML テンプレートに入っていないか、両ファイルを全件確認する。
4. 外部リンクには `rel="noopener noreferrer"` を付ける。

**テスト**
- `tests/ui-escaping.test.ts` を新規作成: `escapeHtml` / `safeHref` の単体テスト（`<img src=x onerror=alert(1)>`, `javascript:alert(1)`, `https://nvd.nist.gov/...`）。
- 加えて、悪意のある値（title に `<img src=x onerror=alert(1)>`、referenceUrls に `javascript:alert(1)`）を含むレポートを描画したとき、生成された DOM に `img` 要素も `javascript:` の href も存在しないことを検証する。描画関数がモジュール外から呼べない場合は、HTML 文字列を返す純粋関数を `src/popup/render.ts` / `src/dashboard/render.ts` に切り出してテストする（T01 で作った render.ts と統合してよい）。

---

### T09 旧DBと旧エンジンの削除（DOC-09）

**変更内容**
1. 次を削除する: `src/security/cve/cve-database.json`, `src/security/cve/cve-engine.ts`, `src/security/eol/eol-database.json`, `src/security/eol/eol-engine.ts`。
2. `src/detection/engine.ts` のフォールバック（`checkEolStatus` / `checkCveAdvisories` 呼び出し）を削除し、`matchOfflineAdvisories()` の結果のみを使う。
3. これらを import しているテスト（例: `tests/version-check.test.ts` の `checkCveAdvisories`）は、同じ観点を `matchOfflineAdvisories()` で検証する形に**移行**する（観点を減らさない）。移行できない観点があれば報告書に記載する。
4. `advisory-db.json` は変更しない（禁止事項）。

**完了条件**: `grep -rn "cve-engine\|eol-engine\|cve-database\|eol-database" src tests` が 0 件。`npm test` と `npm run build` が緑。

---

### T10 プライバシーポリシーの記述を実装に合わせる（DOC-08）

`PRIVACY_POLICY.md` の日英両方を、次の事実に合わせて修正する。**法的文書のため、修正案を作成したら報告書で「人間の承認が必要」と明記する。**

- Cookie の値: 「値は取得しない」ではなく、「ブラウザ API の仕様上、属性取得時に値も一時的にメモリへ読み込まれるが、名前と属性以外は即座に破棄し、保存・表示・送信しない」。
- content script: 「ユーザー操作時のみ」ではなく、現状は「すべてのページに配置されるが、ユーザーが調査を実行したときにのみ DOM を解析する」（IMPL-08 で将来変更予定である旨は書かない）。
- webRequest: 「閲覧中のすべてのページのメインフレームのレスポンスヘッダーのうち、許可リストに含まれるもの（一覧へのリンク）を、タブを閉じるかブラウザを終了するまでセッションストレージに保持する」。
- 外部送信がないこと、履歴がローカルのみであることは現状どおり。
- `Last updated` を作業日に更新する。

---

### T11 バージョン 1.6.6 への更新とドキュメント整合

1. `docs/MAINTENANCE_GUIDE.md` §1.2 のチェックリストに従い、すべてのファイルを `1.6.6` に更新する（`public/manifest.json`, `package.json`, `package-lock.json` の自パッケージ version, `src/detection/rules/index.ts` の `RULES_VERSION`, service-worker / popup / dashboard のフォールバック文字列, ルートと `src/` の `popup.html` / `dashboard.html` のバッジ, `README.md` のバッジ）。manifest は 3 要素（`1.6.6`）とする。
2. `README.md` の「単体テスト実行 (Vitest / 全125テスト)」等の古い件数を実数に直す。
3. `docs/MAINTENANCE_GUIDE.md` §2.8「既知の制限」に、今回解消したもの・残るものを反映する。
4. `docs/DETECTION_SPECIFICATION.md` §6.2 に、バックポート考慮が「第1段階（Needs Review 扱い）」として実装されたことを追記し、§4 の図の Next.js → React を表と同じ `possible` に直す。
5. `docs/REVIEW_v1.6.5.md` は**変更しない**（レビュー記録のため）。

---

### T12 E2E 追加・最終確認・完了報告書

1. `test-server/server.mjs` にルートを追加する: `/bootstrap-only`（Bootstrap 5 のクラスのみ・Tailwind なし）、`/distro-apache`（`Server: Apache/2.4.41 (Ubuntu)`）。
2. `scripts/test-e2e-smoke.mjs` に追加する:
   - ダッシュボードの調査履歴で「表示」「削除」をクリックし、CSP 違反のコンソールエラーが 0 件で、削除後に履歴件数が減ること。
   - `/bootstrap-only` で Tailwind CSS が検出されないこと。
   - `/distro-apache` で Apache が「Needs Review」になること。
3. （夜間モードではこの手順を飛ばす）`npm run build && npm run test:e2e` を実行する。E2E は Chrome をヘッドフル起動するため、画面のない環境では `xvfb-run -a npm run test:e2e` を使う。それも不可能な場合は実行不可として報告書に記載する（失敗とは区別する）。外部サイト（GitHub.com）の項目は soft fail 扱いのままでよい。
4. `node scripts/dev/check-v1.6.6.mjs --static` で静的検査を確認する。この時点では C11（完了報告書）のみ FAIL になるのが正常。
5. `docs/dev/v1.6.6/REPORT_TEMPLATE.md` をもとに `docs/dev/v1.6.6/COMPLETION_REPORT.md` を作成する（§7）。
6. `node scripts/dev/check-v1.6.6.mjs`（E2E を実行できる環境なら `--e2e` 付き）を実行する。結果は `docs/dev/v1.6.6/check-result.json` に保存される。その結果で報告書の §1・§4 を更新し、報告書・check-result.json・WORKLOG をまとめてコミットする。

---

## 5. 横断的な実装ルール

- TypeScript の `strict` を維持する。`any` の新規使用は避け、やむを得ない場合はコメントで理由を書く。
- ユーザーに表示する文言は日本語。既存のトーン（です・ます、短文）に合わせる。
- 新しい型フィールドは任意（`?`）で追加し、過去の履歴データ（`chrome.storage.local` 内の旧レポート）を読み込んでも壊れないようにする。
- 正規表現はルール JSON 内でエスケープ（`\\`）に注意する。追加・変更した正規表現は必ず陽性・陰性の両方のテストを付ける。
- 処理時間: 1 回の調査で content-script と MAIN world の処理が大きく遅くならないこと（目安として新たなループは要素数の上限を設ける）。

## 6. 最終確認コマンド

```bash
npm ci
npm test                      # typecheck + リンク検査 + vitest
npm run build
npm run advisories:validate
npm run advisories:verify-nvd
npm run test:e2e              # 画面がなければ xvfb-run -a npm run test:e2e
node scripts/dev/check-v1.6.6.mjs
```

## 7. 完了報告書

- テンプレート: `docs/dev/v1.6.6/REPORT_TEMPLATE.md`
- 出力先: `docs/dev/v1.6.6/COMPLETION_REPORT.md`
- 必ず含めること: 各タスクの結果（完了 / 一部完了 / 未完了）、実行したテストコマンドと件数（passed / skipped / failed）、解除した受け入れテストの一覧、`check-result.json` の要約、指示からの逸脱と判断理由、人間の確認が必要な事項、変更ファイル一覧（`git diff --stat main...HEAD`）。
- 推測で「完了」と書かない。実行していないテストは「未実行」と書く。

## 8. 人間が行うこと（エージェントは行わない）

1. ポップアップ・ダッシュボードの目視確認（未観測バッジ、ディストリ版バッジ、リンクの表示）。
2. `PRIVACY_POLICY.md` の文言承認と、Chrome Web Store のプライバシー欄・データ開示との整合確認。
3. PR の作成・レビュー・マージ、v1.6.6 のストア提出。
