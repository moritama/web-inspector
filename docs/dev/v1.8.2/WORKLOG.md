# v1.8.2 作業記録

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

## T01 設計  (2026-11-21 20:38)
- 変更ファイル: docs/dev/v1.8.2/design/T01.md（新規）, tests/distro-confidence-display.test.ts（新規）, tests/test-server-distro-multi.test.ts（新規）
- 判断したこと:
  - 「確信度がちょうど 1 回」は OS の推定の確信度（「確信度」の後に高・中・低）を数え、検出の確信度（数値・英語）は数えない。§3.2-1 で確信度入りのままとされた eolInfo.note（説明の全文）は数えない。CSV は列「OSの推定」で 1 回、ポップアップの一覧は 0 回（既存の検出の確信度バッジだけ）と解釈した
  - ポップアップの一覧の行を Vitest で確かめるため、行の HTML を src/popup/render.ts の renderTechRowHtml(tech) に切り出す方針にした（挙動は変えない）
  - formatDistroReleaseWithConfidence は、推定なし（第三者・バックポート・none）では「推定なし」のまま確信度を付けない。v1.8.1 以前の確信度入りの label が付いていても確信度は 1 回
  - 「ディストリ版」の title の全文は「ディストリ版（バックポートの可能性）: <distroHint>」とし、テストは「バックポートの可能性」を含むことだけを見る
  - 候補が 2 件以上になる確認ページが無いので /distro-multi-candidate を足す。版は対応表から取り、またがる版が無ければヘッダーを返さない
  - E2E（ポップアップ 450px）は、ポップアップのページで chrome.runtime.sendMessage を包んでタブ ID を足し、#rescanBtn を押す方式で仕様を書いた（製品のコードに分岐を足さない）
  - 期待値を変えた既存テストは無い
- 外部の事実: Playwright の addInitScript の評価の時点と、拡張機能のページの開き方 — https://playwright.dev/docs/api/class-page#page-add-init-script 、https://playwright.dev/docs/chrome-extensions （2026-11-21）。setViewportSize の引数は確かめられなかったので使わない
- 未解決: v1.8.1 以前に保存したレポートの eolInfo.label（確信度入り）を、ダッシュボードの EOL バッジがそのまま出すのは直さない（保存データを書き換えない）

## T01 実装  (2026-11-21 20:51)
- 変更ファイル: src/detection/distro-inference.ts, src/shared/distro-display.ts, src/background/service-worker.ts, src/popup/render.ts, src/popup/popup.ts, src/popup/popup.css, test-server/server.mjs, scripts/test-e2e-smoke.mjs
- 判断したこと:
  - `judgeDistroEol` で `eolInfo.label` から確信度表示を除去しリリース名のみ（`candidateNames.join(' / ')`）を設定。`eolInfo.note` は仕様どおり確信度入りのまま保持
  - `formatDistroReleaseDisplay` の分岐 (2) を削除し、`formatDistroReleaseWithConfidence` を新設・export。第三者・バックポート・none の推定なし時は「推定なし」（確信度なし）、推定あり時はリリース名に「（推定・確信度 X）」をちょうど1回付与
  - `src/background/service-worker.ts` の EOL 指摘文（`eolObserved`, `eolDescription`）および `SEC-DISTRO-CVE` の `observed` で `formatDistroReleaseWithConfidence` を使用
  - `src/popup/render.ts` に `renderTechRowHtml(tech)` を新設・export。ディストリ版バッジを `.item-meta` に短縮形「ディストリ版」として配置し、`title` に全文「ディストリ版（バックポートの可能性）: <distroHint>」を設定（エスケープ適用）。`.item-side` からは除外
  - `src/popup/popup.ts` の技術一覧生成を `renderTechRowHtml` に置き換え
  - `src/popup/popup.css` で `.item-main` に `flex: 1 1 auto; min-width: 0;`、`.item-side` に `flex-shrink: 1; flex-wrap: wrap; justify-content: flex-end;` を設定
  - `test-server/server.mjs` に `/distro-multi-candidate` を追加し、同一系統・同一製品で 2 以上のリリース候補にまたがる版を動的に抽出して `Server` ヘッダーを出力
  - `scripts/test-e2e-smoke.mjs` に幅 450px でのポップアップ表示検証（`.item-main` 幅、横スクロールなし、ディストリ版バッジの有無確認）を追加
- 外部の事実: なし（設計メモの範囲内）
- 未解決: なし

## T02 設計  (2026-11-21 20:58)
- 変更ファイル: docs/dev/v1.8.2/design/T02.md（新規）, tests/content-script-iife-build.test.ts（新規）, tests/ci-content-script-iife.test.ts（新規）
- 判断したこと:
  - 2 回注入の SyntaxError は、ビルドの出力を node:vm の同じコンテキストで 2 回実行して再現・確認する（同じフレームの isolated world に classic script として 2 回評価されるのと同じ条件）。今の出力は 2 回目で「Identifier 'W' has already been declared」になり、iife で出すと 2 回ともエラーにならずリスナーは 1 回だけだった
  - 2 段目のビルドは vite.config.ts のプラグイン（closeBundle で build()）から起動する。package.json の build スクリプトの書き換えは K2.1 の「scripts の追加のみ」の外になるため。設定は contentScriptBuildConfig(outDir) として export し、configFile: false・publicDir: false・emptyOutDir: false・format iife・inlineDynamicImports: true。出力先は 1 段目の解決後の outDir
  - テストは npm run build を使わず、Vite の build() に vite.config.ts を渡し outDir を os.tmpdir() に上書きして確かめる（リポジトリの dist に触らない）
  - CI のチェック scripts/ci/check-content-script-iife.mjs の基準は総合チェック C20 と同じ（const・let・class・var・import・export を不合格、関数式の即時実行で始まれば合格）。ファイルが無ければ不合格。ci.yml には build の後に手順を 1 つ足す
  - 「IIFE の後にトップレベルの const が続く」形は §5.1 の基準（先頭）の外なので CI のチェックのテストに入れず、実際の出力の 2 回実行のテストで確かめる
  - E2E は isolated world の addListener の呼び出しを数える方式で仕様を書いた（ページのコンソールに isolated world のエラーが出ないことがあるため、調査の結果の注入の失敗も見る）
  - 期待値を変えた既存テストは無い
- 外部の事実: Rollup の output.format iife・inlineDynamicImports・name — https://rollupjs.org/configuration-options/ 、Vite の build()・configFile・apply・configResolved・closeBundle・emptyOutDir — https://vite.dev/guide/api-javascript 、https://vite.dev/guide/api-plugin 、https://vite.dev/config/build-options 、chrome.scripting.executeScript の files・world の既定 ISOLATED — https://developer.chrome.com/docs/extensions/reference/api/scripting （いずれも 2026-11-21）。同じ拡張機能の content script が同じフレームで isolated world を共有することは文書に明記が無く、不具合の報告と手元の再現で確かめた
- 未解決: npm run watch で closeBundle が再ビルドごとに呼ばれるかは確かめていない（受け入れ条件の外）

## T02 実装  (2026-11-21 21:07)
- 変更ファイル: vite.config.ts, scripts/ci/check-content-script-iife.mjs（新規）, .github/workflows/ci.yml, src/background/service-worker.ts, scripts/test-e2e-smoke.mjs
- 判断したこと:
  - `vite.config.ts` でメインビルドの入力から `content-script` を外し、2 段目ビルド用設定関数 `contentScriptBuildConfig(outDir)` を export。`contentScriptIifePlugin` プラグインの `closeBundle` フックから 1 段目の解決後 `outDir` を渡して `build(contentScriptBuildConfig(outDir))` を呼び出す構成を実装
  - `scripts/ci/check-content-script-iife.mjs` を新設し、`checkIifeSource(text)` と `checkContentScriptIife(options)` を export。先頭コメントや `use strict` を除いた本文がトップレベル宣言や import/export で始まらず、即時実行関数式で始まるかを総合チェック C20 と同等の基準で判定。CLI では `--file` オプションに対応し、終了コードと GitHub Actions 形式のエラーログを出力
  - `.github/workflows/ci.yml` の `verify` ジョブで、`npm run build` および `check-size.mjs` の直後に `node scripts/ci/check-content-script-iife.mjs` を実行する手順を追加
  - `src/background/service-worker.ts` の `chrome.scripting.executeScript` 呼び出し直前コメントに、content-script.js が IIFE で出力されている旨を明記
  - `scripts/test-e2e-smoke.mjs` の検証 1 に、同一タブへの複数回調査で `already been declared` や `注入に失敗` が出ないこと、isolated world 内のリスナー重複登録がないこと、二重注入防止の印を消した際の再登録動作を検証するケースを追加
- 未解決: なし

## T03 設計  (2026-11-22 00:30)
- 変更ファイル: docs/dev/v1.8.2/design/T03.md（新規）, tests/cookie-scope.test.ts（新規）, tests/cookie-store.test.ts（新規）
- 判断したこと:
  - Cookie のスコープは名前ごとに host > domain > unknown の強い方を残す。chrome.cookies は hostOnly、Set-Cookie は Domain 属性（値が空でなければ、ホストと同じ値でも domain）、document.cookie だけの名前は unknown（H1・H3）
  - 根拠の cookie-name に属性 `cookieScope` を足す（detail の文言は T03 では変えない。注記は T04）
  - 確信度 35 に下げた技術は今の採用しきい値（50 未満を捨てる）で一覧から消え、「GA は low・possible」を確かめられない。そこで、下げる前が 50 以上だった技術にだけ `cookieScopeDowngraded: true` を付けてしきい値の対象から外す。下げる前から 50 未満のもの（親ドメインの csrftoken だけなど）は従来どおり出さない（警告を増やしすぎない）
  - consolidateCandidates の「*_session と XSRF-TOKEN で 70」は、どちらも host でないときは上げない（H2 に合わせる）
  - hostOnly が真偽値でない Cookie（既存テスト・合成データ）は従来どおり host とした。Chrome の Cookie.hostOnly は必須の真偽値で実際の調査では起きず、既存テストの 20 件以上が hostOnly を書いていないため。domain の先頭の `.` などからは推測しない（H1）
  - D-3 は `resolveCookieStoreId(tabId, cookiesApi?)` を新設し、`getInspectedCookies(url, tabId?)` が通常と分割 Cookie の両方の getAll に storeId を渡す。見つからない・API が無い・例外・タブ ID なしのときは storeId のキーを付けない（既存の IMPL-11 の完全一致を壊さない）。executeInspection は (URL, タブ ID) を渡す
  - 実装の前に、新しいテストは機能が無いことが理由で失敗する（cookie-scope 19 件、cookie-store 11 件）。既存の detection・service-worker・test-hygiene は通る（135 件）。期待値を変えた既存テストは無い
- 外部の事実: chrome.cookies の getAllCookieStores・CookieStore（id・tabIds）・getAll の storeId と partitionKey・Cookie.hostOnly — https://developer.chrome.com/docs/extensions/reference/api/cookies 、manifest の incognito（既定は spanning）— https://developer.chrome.com/docs/extensions/reference/manifest/incognito 、Set-Cookie の Domain 属性と host-only-flag — https://www.rfc-editor.org/rfc/rfc6265 §5.2・§5.2.3・§5.3（いずれも 2026-11-22）。spanning で storeId を省略すると通常の保存先を読むことは指示書 §4.5（2026-11-19 の確認）による
- 未解決: Set-Cookie はヘッダーの記録（sanitizeHeaders）で落とされるため、実際の調査では Set-Cookie の経路はほぼ使われない（検出エンジンの入力としてテストした）。下げた技術に後から連動の根拠が足されて引き上げられたときも `cookieScopeDowngraded` が残るので、T04 の注記ではその場合の扱いを決める必要がある

## T03 実装  (2026-11-22 00:40)
- 変更ファイル: src/shared/types.ts, src/detection/engine.ts, src/background/service-worker.ts
- 判断したこと:
  - `src/shared/types.ts`: `CookieScope`（`'host' | 'domain' | 'unknown'`）を定義し、`Evidence.cookieScope` および `DetectedTechnology.cookieScopeDowngraded`（任意プロパティ）を追加
  - `src/detection/engine.ts`:
    - Cookie 名の収集を `Set<string>` から `Map<string, CookieScope>`（`cookieScopes`）に変更。スコープの優先順位（host > domain > unknown）に従って合成
    - chrome.cookies は `hostOnly === false` なら `domain`、真偽値以外または `true` なら `host`
    - Set-Cookie は先頭の `;` より後にある属性から大文字小文字を無視して `domain` 属性を抽出し、値が空でなければ `domain`、それ以外（属性なし・値が空）は `host`
    - document.cookie は `unknown`
    - `case 'cookie'` で `Evidence` に `cookieScope` を付与
    - 根拠がすべて `cookie-name` かつどれも `host` でない場合、確信度を 35（low / possible / direct）に引き下げ、下げる前の確信度が 50 以上だった場合のみ `cookieScopeDowngraded: true` を設定
    - 採用しきい値フィルタで `cookieScopeDowngraded === true` を除外対象から外して一覧に残す
    - `consolidateCandidates` で Laravel のセッション＋XSRF-TOKEN による 70 への引き上げについて、根拠がすべて `cookie-name` かつ非 host の場合は引き上げをスキップ
  - `src/background/service-worker.ts`:
    - `CookieStoreLookup` 型を定義し、`resolveCookieStoreId(tabId, cookiesApi?)` を新設・export。引数が 2 つ未満のときは `chrome.cookies` を使用し、指定の `tabId` を含む保存先の `id` を解決（見つからない・例外時は `undefined`）
    - `getInspectedCookies(url, tabId?)` を更新し、`resolveCookieStoreId(tabId)` で得られた `storeId` があれば `{ storeId }` を通常 Cookie および CHIPS の `getAll` の両方に渡し、未定義の場合はキー自体を付与しない
    - `InspectionDependencies.getInspectedCookies` に `tabId?: number` を追加し、`executeInspection` から `deps.getInspectedCookies(url, currentTabId)` で呼び出すよう配線
- 外部の事実: なし（設計メモの範囲内）
- 未解決: なし

## T04 設計  (2026-11-22 01:35)
- 変更ファイル: docs/dev/v1.8.2/design/T04.md（新規）, tests/cookie-scope-note.test.ts（新規）, tests/cookie-secure-breakdown.test.ts（新規）, tests/test-server-parent-cookie.test.ts（新規）
- 判断したこと:
  - 根拠の注記は新設の `formatCookieScopeNote(tech, cookies?)`（src/shared/cookie-scope-note.ts）で組み立て、Markdown の §4（表の後）・§14（技術の節の中）とダッシュボードの「判定根拠」の後に出す。ポップアップ・CSV には出さない（§4.2 が挙げていないため。450px の見え方は変わらない）
  - 注記の条件は `cookieScopeDowngraded === true` かつ根拠がすべて host でない `cookie-name`。T03 の未解決（連動検出で後から根拠が足されても印が残る）は、注記の側で根拠を確かめて出さないことにした（H2 と揃える。印の付け方は変えない）
  - 注記の趣旨の語句（「別サイト」「このホスト単体での利用は確認できていません」）は注記 1 つに 1 回。Cookie 名が複数・同じ名前が複数の親ドメインのケースを別にテストした
  - Secure の内訳は `SecurityCheckResult.parentDomainCookieCount?`（hostOnly === false の件数。1 以上のときだけ）に持ち、`observed` は変えない（ポップアップと差分に影響させない）。Markdown §5 とダッシュボードの観測値に「うち N 件は親ドメインのスコープ」を添える。0 件・旧レポートでは何も添えない
  - 確認ページは test-server の `/parent-cookie-issuer`（`*.localtest.me` なら `Domain=localtest.me`、`*.example.test` なら `Domain=example.test` の `_ga`）と `/parent-cookie-target`。名前解決できない環境の代わりに `/etc/hosts` へ `issuer.example.test`・`app.example.test` を足す手順をページに書く。`/clear-cookies` は親ドメインの `_ga` も消す
  - 実装の前は、新しいテストが機能が無いことを理由に失敗する（56 件中 40 件失敗。`npx tsc --noEmit` は新規モジュールが無いため失敗）。test-hygiene は通る。期待値を変えた既存テストは無い
- 外部の事実: localtest.me とそのサブドメインが 127.0.0.1 に解決されること — https://weblogs.asp.net/owscott/introducing-testing-domain-localtest-me 、`.test` の予約 — https://datatracker.ietf.org/doc/html/rfc6761#section-6.2 、Domain 属性と host-only-flag・domain-match — https://www.rfc-editor.org/rfc/rfc6265 §5.1.3・§5.3 、chrome.cookies の hostOnly・domain — https://developer.chrome.com/docs/extensions/reference/api/cookies （いずれも 2026-11-22）。ルーターの DNS リバインディング対策で localtest.me が解決できないことがある点は一次資料で確かめられず、代わりの手順を書く理由としてだけ使う
- 未解決: Secure の内訳は HTTPS でしか出ないため、テストサーバー（HTTP）では目視できない（Vitest で確かめる）

## T04 実装  (2026-11-22 01:38)
- 変更ファイル: src/shared/types.ts, src/shared/cookie-scope-note.ts（新規）, src/security/cookies.ts, src/export/markdown.ts, src/dashboard/render.ts, src/dashboard/dashboard.ts, test-server/server.mjs
- 判断したこと:
  - `src/shared/cookie-scope-note.ts` を新設し `formatCookieScopeNote(tech, cookies?)` を実装。`tech.cookieScopeDowngraded === true` かつ `tech.evidence` のすべてが `type === 'cookie-name'` かつ `cookieScope !== 'host'` の場合のみ注記文を生成。Cookie 名とドメイン（`cookies` 内で `c.hostOnly === false` のもの）を出現順・重複除外で収集し、「同一ドメインの別サイトで発行された可能性があり、このホスト単体での利用は確認できていません」をちょうど1回付与
  - `src/shared/types.ts`: `SecurityCheckResult` に `parentDomainCookieCount?: number` を追加
  - `src/security/cookies.ts`: `checkCookies` で各 `CookieIssue` について入力 Cookie の `typeof rawCookie.hostOnly === 'boolean' && rawCookie.hostOnly === false` を保持し、`SEC-COOKIE-SECURE`、`SEC-COOKIE-SECURE-CSRF`、`SEC-COOKIE-SECURE-GENERAL` で親ドメイン件数が 1 以上の場合に `parentDomainCookieCount` を付与。`observed` 文字列は変更せず維持
  - `src/export/markdown.ts`: §4 の表後に親ドメイン Cookie 根拠技術の注記ブロック（`> [!NOTE]`）を追加。§14 の技術エビデンス詳細節の末尾に `- ※ ${注記}` を追加。§5 の観測値列に `parentDomainCookieCount > 0` の場合「（うち N 件は親ドメインのスコープ）」を添える
  - `src/dashboard/render.ts`: `renderFullTechnologiesHtml` に第 3 引数 `cookies`（任意）を追加し、「判定根拠 (Evidence)」の直後に注記 HTML を出力。`renderFullSecurityHtml` の観測値に親ドメイン件数を付記
  - `src/dashboard/dashboard.ts`: `renderFullTechnologies` に `report.cookies` を渡すよう更新
  - `test-server/server.mjs`: `TEST_PAGES` に `/parent-cookie-issuer` と `/parent-cookie-target` を追加し、`getStartupLines` に起動時 URL 行を追加。リクエスト Host から `localtest.me` または `example.test` を判定し、`/parent-cookie-issuer` で親ドメインの `_ga` を発行（GA スクリプトは不含）、DNS リバインディング対策の `/etc/hosts` 手順を記載。`/parent-cookie-target` は案内のみ。`/clear-cookies` で親ドメインの `_ga` 期限切れ（Max-Age=0）を設定
- 外部の事実: なし（設計メモの範囲内）
- 未解決: なし
