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

## T05 設計  (2026-11-22 02:31)
- 変更ファイル: docs/dev/v1.8.2/design/T05.md（新規）, tests/secure-context.test.ts（新規）, tests/connection-local-count.test.ts（新規）, tests/report-lint.test.ts（既存の 2 件の期待値を変更）
- 判断したこと:
  - D-1: `isSecureContextUrl(url)` を `src/shared/secure-context.ts` に新設する前提。真は https・wss・file・localhost・*.localhost・127.0.0.0/8・[::1]（H7）。§4.3 の偽の行はすべて陰性テストにし、`isIpOrLocalHost()` が真にする範囲（LAN の IP・.local）と、localhost や 127 を含むだけのドメインも偽にした
  - `checkHttpHeaders` の `isSecureContext` は既存の第 4 引数 `options` の任意の項目にした（省略時は `isHttps`。既存の呼び出しとテストを変えない）。切り替えるのは COOP・COEP の分岐だけで、HSTS・Cookie の Secure・混在コンテンツ・CORP・SEC-HTTPS-01 は「localhost と LAN の IP で COOP・COEP 以外の項目が一致する」テストで変わらないことを確かめる
  - D-2: `localCount` は常に数値で返す（型は任意）。localCount の無い保存済みレポートは、表（connections）から数え直さず「総数 − First − Third」で求める（履歴の保存の上限で表は 50 件に切り詰められるが総数は残るため）。求められないときは null で、Markdown・ダッシュボードに Local を出さない（0 と表示しない）。共通の関数 `resolveLocalConnectionCount`（src/shared/connection-counts.ts）
  - R10: JSON に localCount があれば 総数 = 合計、無ければ First + Third ≤ 総数。Markdown は Local の行があれば合計を確かめ、無い場合は JSON に localCount があれば不合格（過去の Markdown は検査しない）。既存のフィクスチャはこの規則で合格する
  - 既存テストの変更: tests/report-lint.test.ts の「全 9 項目」の 2 件（`toBe(9)` を CHECK_DEFINITIONS の件数と R01〜R10 の ID に替えた）。理由は R10 の追加で項目が 10 になるため（設計メモ「期待値を変えた既存テスト」）
  - 実装の前は、新しい 2 ファイルが新規モジュールの無いことで読み込みに失敗し、report-lint.test.ts の 1 件が R10 の無いことで失敗する（赤を確認）。`npx tsc --noEmit` の失敗は新規モジュール・`localCount`・`isSecureContext` だけ。test-hygiene は通る。§4.3 の表は、一時ディレクトリの参照実装で全行が期待どおりになることを確かめた
- 外部の事実: W3C Secure Contexts「Is origin potentially trustworthy?」— https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy （§3.1。CRD 2023-11-10）、HTML の COOP・COEP の non-secure context の扱い — https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers ・ #obtain-an-embedder-policy （いずれも 2026-11-22 確認）
- 未解決: 指示書 §4.3 は「W3C Secure Contexts §3.2（Is origin potentially trustworthy?）」と書くが、現行の文書では §3.1（§3.2 は Is url potentially trustworthy?）。規則の中身は H7 と同じなので作業は止めず、設計メモに正しい節を書いた。COEP の手順 2 の末尾の語句は逐語では確かめられていない（判定の向きは COOP と同じ）
- テストレビューへの対応: 採用 1 件・却下 0 件
  - 採用: localCount の無い保存済みレポートで Local が 0（総数 = First + Third）でも「Local … 0 件」を出す設計だと、tests/report-lint.test.ts の回帰用フィクスチャの完全一致比較（保存済み .md には Local の行が無い）が必ず失敗する、という矛盾の指摘。§4.4「Local の行を出さない」「0 と表示しない」に合わせ、localCount が無ければ求めた値が 1 以上のときだけ Local を出す（localCount があれば 0 でも出す）ように設計メモを直し、tests/connection-local-count.test.ts に陰性・対照・フィクスチャの §9 のテストを足した。フィクスチャの .md は変えていない

## T05 実装  (2026-11-22 02:45)
- 変更ファイル: src/shared/secure-context.ts（新規）, src/shared/connection-counts.ts（新規）, src/shared/types.ts, src/security/headers.ts, src/security/engine.ts, src/security/domain-analyzer.ts, src/export/markdown.ts, src/dashboard/render.ts, scripts/report-lint.mjs, test-server/server.mjs
- 判断したこと:
  - `src/shared/secure-context.ts` を新設し `isSecureContextUrl(url)` を実装。スキーム（https:, wss:, file:）、ホスト（localhost, *.localhost, 127.0.0.0/8, [::1]）を判定。IPv4 は 4 オクテット各 0-255 かつ先頭 127 を正規表現と数値で検証し、不正な URL や文字列以外の入力は例外を投げずに false を返却
  - `src/security/headers.ts`: `CheckHttpHeadersOptions` に `isSecureContext?: boolean` を追加し、`checkHttpHeaders` 内で `const secureContext = options?.isSecureContext ?? isHttps;` として COOP および COEP の対象外判定（not-applicable）を `!secureContext` に変更。対象外時の説明文に「安全なコンテキスト（HTTPS・localhost）」の語句を反映。HSTS・CORP 等の他の判定は `isHttps` のまま維持
  - `src/security/engine.ts`: `checkHttpHeaders` の options に `isSecureContext: isSecureContextUrl(input.url)` を渡すよう更新
  - `src/shared/types.ts`: `ExternalConnectionsAnalysis` に `localCount?: number` を追加
  - `src/security/domain-analyzer.ts`: `analyzeExternalConnections` で `resInfo.isIpOrLocal` 時に `localCount` をカウントし、戻り値に含めるよう実装（常に数値型で返却）
  - `src/shared/connection-counts.ts` を新設し、`resolveLocalConnectionCount(analysis)` および `shouldShowLocalConnectionCount(analysis)` を実装。`localCount` が 0 以上の整数ならその値を採用し、未定義（旧レポート）なら `totalConnections - firstPartyCount - thirdPartyCount` で算出（差が負または不正値なら null）。表示判定は、`localCount` があれば 0 件でも表示し、未定義なら 1 件以上の場合のみ表示（0 件や null は非表示）として回帰用フィクスチャ整合性を維持
  - `src/export/markdown.ts`: §9 の Third-Party 行の直後に、表示対象の場合のみ `- **Local（ローカル・IP アドレス）:** N 件` を出力
  - `src/dashboard/render.ts`: `renderExternalConnectionsHtml` で表示対象の場合のみ `(自社/First-Party: A, 外部/Third-Party: B, ローカル/Local: <strong>C</strong>)` と出力
  - `scripts/report-lint.mjs`: `CHECK_DEFINITIONS` に `R10`（pending: false）を追加し、`checkConnectionTotalsIncludeLocal(report, markdown)` を実装。JSON の `total === first + third + local` および Markdown §9 の箇条書き内訳との整合性を検証（旧レポートで localCount なし・Local 行なしの場合は合格扱い）
  - `test-server/server.mjs`: `/https-only-headers` の説明文を localhost で通常判定、LAN の IP で対象外となる旨に更新
- 外部の事実: なし（設計メモの範囲内）
- 未解決: なし

## T06 設計  (2026-11-22 03:10)
- 変更ファイル: docs/dev/v1.8.2/design/T06.md（新規）, tests/advisory-sources.test.mjs（新規）, tests/advisory-sources-compat.test.ts（新規）, tests/advisory-db-invariants.test.ts（T06 の describe を追加、既存 1 件の期待値を変更）, tests/advisory-distro-pipeline.test.mjs・tests/advisory-pipeline.test.mjs（既存の期待値を変更）
- 判断したこと:
  - 最上位の `sources` は §5.2 の表のうち DB に入る 6 つ（NVD・GitHub Advisory Database・Ubuntu・Debian・endoflife.date・CISA KEV）。Ubuntu・Debian は distro 節があるときだけ。curated・PSL・Launchpad・sources.debian.org は載せない。形は `distro._source` と同じ（name・url・ecosystem・license・licenseNote?・retrievedAt・recordCount）
  - catalog.json は変更禁止なので、出典の定義は `scripts/advisories/lib/sources.mjs`（新規）の定数に置く。値は設計メモの JSON。Debian は `license: null` と licenseNote「ライセンスの明記なし（出典のみ表示）」（§5.3）。`distro._source` は catalog から作る今のまま
  - retrievedAt は出典ごとのスナップショットのいちばん新しい取得日時、recordCount はその出典に由来して DB に入った件数。スナップショットが無ければ null と 0（値を作らない）。Ubuntu・Debian は `distro._source` の値を写す
  - validateDb: 2.4 では全要素がオブジェクトで license か licenseNote を持つことを検査。2.3 以前の文字列の配列はこれまでどおり受け付ける。拡張機能の側は `normalizeAdvisoryDbSources` で新旧をそろえ、`getAdvisoryDbMetadata().sources` は名前の `string[]` のまま、構造化した出典は任意の `sourceRecords` に入れる。古い文字列からライセンス・件数・日時を作らない（null）
  - CI: `scripts/ci/check-data-sources.mjs`（新規）を ci.yml に足す。THIRD_PARTY_NOTICES.md（T07 で作る）が無ければ照合を飛ばして警告だけにする（T07 は scripts/ci/ を変えられないので、照合の仕組みは T06 で入れる）
  - PSL: `renderPslGeneratedTs` の先頭のコメントに MPL 2.0 の 3 行と元のファイルの URL を足す。生成ファイルは夜のシェルの spec:generate で作り直される
  - 既存テストの変更（全件）: tests/advisory-distro-pipeline.test.mjs の schema 2.3 の describe の 3 か所（`'2.3'` → `'2.4'`／`OUTPUT_SCHEMA_VERSION`）、tests/advisory-pipeline.test.mjs の「strict 検証 (schema 2.3)」1 件（2.4 に）、tests/advisory-db-invariants.test.ts の getAdvisoryDbMetadata の 1 件（受け付けるスキーマに 2.4 を追加）。理由はいずれも H10 でスキーマが 2.4 に上がるため。`db.sources` の全体比較をしている既存テストは無い
  - 実装の前は、新しいテストが「機能が無い」ことで失敗することを確認した（5 ファイル・47 件が失敗。schema が 2.3、sources が文字列、`normalizeAdvisoryDbSources` と check-data-sources.mjs が無い、PSL の表示が無い）。互換のテスト（照合が sources の形に依存しない、2.3 の文字列の配列を通す）は今も通る。`npx tsc --noEmit` と tests/test-hygiene.test.ts は通る
- 外部の事実: OSV data sources — https://google.github.io/osv.dev/data/ （GHSA CC-BY 4.0、Ubuntu CC-BY-SA 4.0、Debian は記載なし）、https://github.com/github/advisory-database （CC-BY 4.0）、https://github.com/canonical/ubuntu-security-notices （CC BY-SA 4.0）、https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE （MIT、Copyright 2020 endoflife.date contributors）、https://github.com/cisagov/kev-data （CC0）、https://publicsuffix.org/list/public_suffix_list.dat （先頭の MPL 2.0 の表示）。いずれも 2026-11-22 確認
- 未解決:
  - NVD の表示文の一字一句（指示書は「uses the NVD API」、検索の要約には「uses data from the NVD API」）は、NVD のページを取得できず確かめられなかった。T06 の DB には英文を入れず、T07 で確かめる
  - catalog.json の `distroSources` の Debian の licenseNote が仮の値（「v1.8.2 で確認」）のままで、`distro._source` に入る。catalog.json は変更禁止のため、人が直すかを判断する

## T06 停止（夜間スクリプトによる自動記録）  (2026-11-22 03:10)
- 理由: 実装の担当が、テストの期待値の変更が必要と判断した: PSL生成ファイルのMPL表示の改行を修正。tests/osv-distro-pipeline.test.mjs:649 はT05のschema 2.3前提（sourcesが単一文字列）の古いテストのため、schema 2.4（オブジェクト配列）のT06仕様と矛盾しておりテスト側の期待値更新が必要です。
- 変更の退避先: git stash の「v1.8.2 T06 stop 20261122-021831」（記録時点で stash@{0}。番号はずれるので git stash list で名前を確認）。夜間ログのフォルダにパッチもある
- 人間に判断してほしいこと: 設計メモとテストを読み、期待値を変えるべきか判断する。変えるなら人がテストを直してコミットし、RETRY_STOPPED=1 で再実行

## T06 実装  (2026-11-22 03:26)
- 変更ファイル: scripts/advisories/lib/sources.mjs（新規）, scripts/ci/check-data-sources.mjs（新規）, scripts/advisories/build-db.mjs, scripts/validate-advisories.mjs, scripts/advisories/lib/psl.mjs, .github/workflows/ci.yml, src/shared/types.ts, src/detection/advisory.ts, src/security/psl-rules.generated.ts
- 判断したこと:
  - `scripts/advisories/lib/sources.mjs` を新設し、`DB_SOURCE_DEFINITIONS` および `buildDbSources` を実装。NVD、GHSA、Ubuntu、Debian、endoflife.date、CISA KEV の6出典について、各上流スナップショットの最新取得日時（`retrievedAt`）と DB 収録件数（`recordCount`）を算出。Ubuntu・Debian は `distroSection` 存在時のみ出力し、`distroSection._source` の値を反映。Debian の `licenseNote` は指示書指定の「ライセンスの明記なし（出典のみ表示）」を設定
  - `scripts/advisories/build-db.mjs` で `OUTPUT_SCHEMA_VERSION = '2.4'` に引き上げ、`buildDbSources` で生成したオブジェクト配列を `db.sources` に設定
  - `scripts/validate-advisories.mjs` でスキーマ 2.4 に対応し、`sources` の全要素に対してオブジェクト型、https の url、空でない name、license または licenseNote の存在、有効な retrievedAt / recordCount などの厳格な検証を追加。2.3 以前の文字列配列との後方互換も維持
  - `scripts/advisories/lib/psl.mjs` の `renderPslGeneratedTs` で先頭コメントに MPL 2.0 のライセンス表記および元の PSL URL を追加。テスト検証（`toContain('Mozilla Public License')`）に合致するよう「This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.」の行構成とし、`src/security/psl-rules.generated.ts` にも反映
  - `scripts/ci/check-data-sources.mjs` を新設し、同梱 DB の `sources` および `distro._source` の各出典に license または licenseNote があることを検査。THIRD_PARTY_NOTICES.md が存在する場合は出典の記載有無（name または url）を照合し、存在しない場合は警告（スキップ）扱いとする。`.github/workflows/ci.yml` に手順を追加
  - `src/shared/types.ts` に `AdvisoryDbSourceRecord` を追加し、`AdvisoryDbMetadata` に `sourceRecords?` を追加
  - `src/detection/advisory.ts` に `normalizeAdvisoryDbSources(raw)` を新設・export し、文字列・オブジェクト・混在・不正な値から `AdvisoryDbSourceRecord[]` を安全に構築。`getAdvisoryDbMetadata` で `sources`（名前の文字列配列）と `sourceRecords`（構造化出典レコード配列）の両方を提供するよう実装
- 外部の事実: なし（設計メモの範囲内）
- 未解決: なし

## T07 設計  (2026-11-22 06:31)
- 変更ファイル: docs/dev/v1.8.2/design/T07.md（新規）, tests/data-sources-display.test.ts（新規）, tests/third-party-notices.test.ts（新規）, tests/advisory-db-invariants.test.ts（T07 の describe を追加。既存の期待値は変えていない）
- 判断したこと:
  - 表示の出典の一覧を `src/shared/data-sources.ts`（新規）の `BUNDLED_DATA_SOURCES`（§5.2 の 7 種類）と `NVD_NOTICE`・`NVD_TERMS_URL`・`DATA_SOURCES_VIEW_ID` に置く前提。名前と URL は同梱 DB の `sources`・`distro._source` と同じにし、一致を同梱 DB を読んでよい advisory-db-invariants で確かめる。PSL は DB に無いが同梱物なので一覧に入れる
  - 「DB の出典がすべて NOTICES にある（CI）」: T06 の `check-data-sources.mjs` は NOTICES が無いと照合を飛ばすが、T07 は `scripts/ci/` を変えられないため、Vitest で「合格し、照合を飛ばさない」「名前と URL の両方が NOTICES にある」を確かめる
  - ダッシュボードはサイドバーに欄を足し、URL のハッシュ `#dataSourcesView` で初期表示をその欄にする（ナビのある id だけ。不正な値は無視）。ポップアップはフッターのリンクで `dashboard.html#dataSourcesView` を開くだけ
  - Markdown は §15 の後に `## 16. データの出典とライセンス`。既存の Markdown の比較（§9 の保存済み .md との比較、§15 の toContain、report-lint の節の切り出し）に影響しないことを確かめた
  - zip: `scripts/package.mjs` を os.tmpdir の作業場所（realpath 済み）で実行し、NOTICES が zip の直下に入ること、無ければ失敗して zip を作らないことを確かめる（zip・unzip が無い環境では skip）
  - endoflife.date の製品説明を使っていないことは、build-db がサイクルの項目だけを使うことをコードで確かめた
  - 実装の前は、新しい 2 ファイルが `src/shared/data-sources` の無いことで読み込みに失敗し、advisory-db-invariants は T07 の 3 件だけ失敗する（既存 34 件は通る）。`npx tsc --noEmit` の失敗は新規モジュールが無いことによるものだけ。test-hygiene は通る
- 外部の事実: NVD の表示文「This product uses the NVD API but is not endorsed or certified by the NVD.」— https://nvd.nist.gov/developers/terms-of-use （ページは JavaScript で描画されるため直接取得できず、検索エンジンの同ページの抜粋で確認）、endoflife.date の MIT の全文 — https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/LICENSE （いずれも 2026-11-22）。他は T06 の確認を引き継ぐ
- 未解決:
  - NVD の Start Here のページは「uses data from the NVD API」という別の言い回し。指示書が資料に挙げる Terms of Use の文を採用した。人が Terms of Use のページをブラウザで開いて一字一句を確かめること
  - catalog.json の Debian の `distro._source` の licenseNote が仮の値（「v1.8.2 で確認」）のまま（T06 の未解決を引き継ぐ。表示は `BUNDLED_DATA_SOURCES` の「ライセンスの明記なし（出典のみ表示）」を使うので画面には出ない）

## T07 実装  (2026-11-22 13:20)
- 変更ファイル: src/shared/data-sources.ts（新規）, THIRD_PARTY_NOTICES.md（新規）, dashboard.html, src/dashboard/render.ts, src/dashboard/dashboard.ts, popup.html, src/popup/popup.ts, src/popup/popup.css, src/export/markdown.ts, scripts/package.mjs, README.md, scripts/test-e2e-smoke.mjs
- 判断したこと:
  - `src/shared/data-sources.ts` を新規作成し、同梱データ 7 種類（NVD, GHSA, Ubuntu, Debian, endoflife.date, CISA KEV, PSL）の定義 `BUNDLED_DATA_SOURCES`、および `NVD_NOTICE`, `NVD_TERMS_URL`, `DATA_SOURCES_VIEW_ID` を定義。Debian はライセンス明記なしとし、NVD には承認・認定を受けていない旨の加工注記を記載
  - リポジトリ直下に `THIRD_PARTY_NOTICES.md` を作成。各出典の名称、URL、ライセンス表記、同梱内容、加工有無を網羅。NVD の利用規定表示文、Ubuntu の CC BY-SA 4.0、Debian の「ライセンスの明記なし」、endoflife.date の MIT 全文（著作権表示含む）、PSL の MPL 2.0 参照および元ファイル・生成ファイル名を記載。環境固有文字列を含まないよう配慮
  - `dashboard.html` のサイドバーに「データの出典」ナビボタン、メイン領域に `dataSourcesView` パネルを追加。`src/dashboard/render.ts` に `renderDataSourcesHtml()` を追加し、NVD 表示文・利用規約リンクおよび 7 出典の情報を安全に描画（XSS 防止・https リンク・インラインハンドラ排除）。`src/dashboard/dashboard.ts` で初期表示時のハッシュ判定 (`applyInitialHashView`) を実装し、`#dataSourcesView` で初期表示を切り替え可能とした（不正ハッシュ時は概要サマリー維持・例外非送出）
  - `popup.html` のフッターに `#dataSourcesLink`（文言: 「出典・ライセンス」）を追加し、クリック時に `dashboard.html#dataSourcesView` を新しいタブで開く処理を `src/popup/popup.ts` に追加。ポップアップ側には一覧や表示文を持たせずリンクのみとし、`src/popup/popup.css` で 450px 幅でも横スクロールが発生しないスタイルを設定
  - `src/export/markdown.ts` に `## 16. データの出典とライセンス` セクションを追加。設計メモの固定文面およびフィクスチャと完全に合致する表を出力
  - `scripts/package.mjs` で zip 作成前に `THIRD_PARTY_NOTICES.md` の存在を検証し、zip アーカイブ直下に同ファイルを同梱するよう修正（失敗時は zip 削除）
  - `README.md` のライセンス節を更新し、コードは MIT、同梱データはそれぞれのライセンスに従う旨（Ubuntu は CC BY-SA 4.0、詳細は THIRD_PARTY_NOTICES.md）を記載
  - `scripts/test-e2e-smoke.mjs` に検証 9（ポップアップ 450px の出典リンク検証およびダッシュボード連携検証）を追加
- 外部の事実: 設計メモ記載の事実・URL（NVD Terms of Use: https://nvd.nist.gov/developers/terms-of-use、endoflife.date LICENSE 全文: https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/LICENSE 等、2026-11-22 確認）を引用
- 未解決: なし

## T08 設計  (2026-11-22 13:28)
- 変更ファイル: docs/dev/v1.8.2/design/T08.md（新規）, tests/header-unobserved-guidance.test.ts（新規）, tests/release-docs-spec-guide.test.ts（新規）, tests/detection.test.ts（既存。AngularJS の入力値だけ変更）
- 判断したこと:
  - 版の一致は既存の spec-integrity・release-docs・release-version・test-hygiene が package.json の版で確かめるので、新しいテストは足さない（v1.8.1 T08 と同じ）。目標の版を前提に、版の直書きの検査と同じ形（引用符付き・`v` 付き・4 つ目付き・エスケープした形）を tests/ 全体にかけたところ、tests/detection.test.ts の AngularJS の入力値が目標の版と同じ文字列だった。入力値と期待値を 1.7.9 に変えた（EOL の判定は 1.x 全体で同じで、判定の期待値は変えていない）。変更後は 0 件
  - D-3 の文言: ヘッダー未観測の Partial の理由を新しい定数 `HEADER_UNOBSERVED_PRESCAN_REASON`（元の文＋「ページを再読み込みしてから、もう一度調べてください」）にする。Markdown §2 は保存された理由を出すだけ（古いレポートに案内を作り足さない）
  - ポップアップには Partial の理由を出す場所が無く、既存の「HTTPヘッダー未取得」の案内は型にも調査の統括にも無いキー（`coverage.networkHeadersObserved`）を条件にしていて一度も出ない。受け入れ条件（ポップアップ 450px）を満たす最小の変更として、条件を `coverage.details.unobservedPreScan === true` に直し、純粋関数 `renderHeaderUnobservedNoticeHtml`（src/popup/render.ts）に切り出す。ダッシュボードの同じ案内も同じ条件にする。450px の見え方は E2E の検証 10 として仕様を書いた（応答のレポートを差し替えて表示を確かめる）
  - 「制限事項」はレポートの Markdown §15 と解釈し、6・7 の 2 項目を足す。ダッシュボードとポップアップに制限事項の欄は新しく作らない
  - DETECTION_SPECIFICATION と MAINTENANCE_GUIDE は起点から変わっていないので、v1.8.2 の変更（A・B・C・D-1・D-2・D-3・E）の要点と、R10・CI の補助スクリプト 2 つ・出典の更新手順を書く。テストは語だけを見る。COOP・COEP の項の「HTTP 接続のページで（は）」は事実と違うので置き換えを陰性テストで求める
  - PRIVACY_POLICY は変更しない（通信も権限も増えない。Cookie は名前と属性だけを扱うまま）。manifest の incognito が spanning のまま、新しい権限が無いことをテストで確かめる
  - 既存テストへの影響: 理由の文を完全一致で比べるテスト・フィクスチャ、ポップアップの案内の有無を比べるテストは無い。§15 は toContain と節の位置だけのテストなので項目を足しても壊れない
  - 実装の前は、新しい 2 ファイルの 30 件が「機能・文書が無い」ことで失敗し、16 件（陰性・互換・検査自身の確認・manifest）は通る。tests/test-hygiene.test.ts と tests/detection.test.ts は通る。`npx tsc --noEmit` の失敗は `renderHeaderUnobservedNoticeHtml` が無いことによるものだけ
- 外部の事実: manifest の `incognito`（既定は spanning。spanning の拡張機能は自分のページをシークレットのタブのメインフレームに読み込めない）— https://developer.chrome.com/docs/extensions/reference/manifest/incognito 、`chrome.cookies`（`cookies` 権限と host permissions、`getAllCookieStores` の `id`・`tabIds`、`getAll` の `storeId`）— https://developer.chrome.com/docs/extensions/reference/api/cookies （いずれも 2026-11-22 確認）
- 未解決:
  - シークレットのタブを調べた結果も、spanning のため通常の `chrome.storage.local` の調査履歴に保存される（v1.8.2 の前からの挙動）。PRIVACY_POLICY の第 3 章には書かれていない。書くかどうかは人が判断する（T08 では変えない）
  - 次の版（一般公開）の版の文字列が tests/advisory.test.ts に 1 件ある（`src/detection/advisory.ts` の一般公開の版に合わせた値）。その版に上げるときに test-hygiene に掛かるので、次の版上げの設計で扱う

