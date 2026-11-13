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

## T02 設計  (2026-11-11 22:46)
- 変更ファイル（新規）: tests/ci-db-release-rehearsal.test.ts, tests/ci-check-size.test.ts, tests/ci-workflow.test.ts, docs/dev/v1.8.0/design/T02.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - 予行は `scripts/ci/rehearse-db-release.mjs` の `rehearseDbRelease({ sourceDir, testCommand, advisoryDbPath, keepWorkDir })` とし、テストではテストのコマンドと DB の場所を差し替える。全体の npm test をテストの中で走らせない（時間がかかり、予行の中で予行のテストが再び走る入れ子になるため）
  - 受け入れ条件 1（現在のツリーで予行が通る）: CI のジョブ db-release-rehearsal で npm test による予行を行う。Vitest の中では、現在のツリーのコピーで版と dataVersion を進め、テストの代わりに scripts/validate-advisories.mjs を走らせて通ることと、元のツリー（manifest と git status）が変わらないことを確かめる
  - 受け入れ条件 2（旧来の書き方のテストを足すと予行が失敗する）: 実装の担当は tests/ を変えられないので、合成の作業ツリーに「manifest の版を完全一致で比べる」検査を置き、元のツリーでは通るのに予行では失敗することを自動のテストにした（対照として「同じリリースか」で書けば通る）。実際のリポジトリに一時的にテストを足す手順は行っていない
  - 受け入れ条件 3（actionlint）: actionlint がある環境でだけ実行する（CI の実行環境に無く、依存も足せないため skipIf）。夜間の実行環境では実行され、現在の ci.yml で合格することを確かめた
  - dataVersion の進め方は「元より後の正しい YYYYMMDD」だけを求める（推奨は翌日）。MB は既存の validate-advisories.mjs に合わせて 1024 × 1024。「超えたら」は `>`。dist や DB が無いときは失敗（安全側）
  - .gitignore で除外されるもの（dist・reports）はコピーしない。node_modules はシンボリックリンク。コピーは元のツリーの外（os.tmpdir()）
  - 合成のツリーの版（3.4.5）と dataVersion（20990101）は合成データで、実際の値への依存ではない
- 確認したこと: 3 ファイルとも実装の前に失敗する。理由は scripts/ci/ のモジュールが無いこと（読み込みの失敗）と、ci.yml にジョブ db-release-rehearsal と check-size の手順が無いこと。`npx tsc --noEmit` は合格
- 外部の事実: GitHub Actions の `::warning` / `::error` はログに注記を作り、`::error` だけでは手順は失敗しない — https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands（2026-11-11）
- 未解決: 予行を全体の npm test で実際に走らせた結果（受け入れ条件 1 の本番）は、実装の後に CI（PR）か人の実行で確かめる。設計の工程ではスクリプトの実行が許可されておらず、一時コピーでの模擬はできなかった

---

## T02 実装  (2026-11-11 22:58)
- 変更ファイル（新規）: scripts/ci/check-size.mjs, scripts/ci/rehearse-db-release.mjs
- 変更ファイル（既存）: .github/workflows/ci.yml
- 判断したこと:
  - scripts/ci/check-size.mjs:
    - G7 の上限値（advisoryDb: 2 MiB, dist: 3 MiB, WARN_RATIO: 0.8）を定義。MB は 1024 × 1024 バイト
    - classifySize は `bytes > limit` で fail、`bytes > limit * 0.8` で warn、境界（80% ちょうど、上限ちょうど）は超えていないものとして判定
    - measureDirBytes でディレクトリ配下の全通常ファイルのサイズを再帰的に合計
    - checkSizes は dist や DB ファイルが存在しない場合に fail とし、CLI 実行時は GitHub Actions の注記（`::warning` / `::error`）を出力し、fail が無ければ終了コード 0、1件でもあれば終了コード 1 で終了
  - scripts/ci/rehearse-db-release.mjs:
    - nextDataVersion は YYYYMMDD の書式・日付妥当性を確認し、UTC の暦で翌日を算出
    - bumpAdvisoryDb は入力を変更せず複製し、dataVersion を進めて integrity を libraries の sha256 で再計算
    - 一時コピーは `os.tmpdir()` 直下に作成。Git 作業ツリーなら `git ls-files`、非 Git なら再帰コピーを使用し、`.git`・`node_modules`・`dist`・`reports` を確実に除外。node_modules はシンボリックリンクを作成
    - コピー内の bump-db-revision.mjs を実行する際、macOS などのシンボリックリンク付き一時ディレクトリで ESM のエントリーポイント判定（`import.meta.url === pathToFileURL(process.argv[1]).href`）が一致するよう `fs.realpathSync` を通したパスを指定。環境変数から GITHUB_OUTPUT を削除
    - 採番失敗時は ok: false で終了。正常時はコピー内 DB を更新して testCommand を実行し、終了コードをそのまま返す
  - .github/workflows/ci.yml:
    - verify ジョブの `Build Extension (Vite)` の直後に `node scripts/ci/check-size.mjs` を追加
    - ジョブ `db-release-rehearsal` を追加。アクションは既存と同じ 40 桁 SHA で固定し、npm ci の後に `node scripts/ci/rehearse-db-release.mjs` を実行。permissions はワークフロー全体の `contents: read` を継承
    - actionlint がエラーなく通過することを確認
- 外部の事実:
  - GitHub Actions の `::warning` / `::error` は注記を作るのみで手順は失敗しないため、終了コード 1 で失敗を伝える — https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands（2026-11-11）
- 未解決: なし

---

## T03 設計  (2026-11-11 23:26)
- 変更ファイル（新規）: tests/hsts-prerelease.test.ts, docs/dev/v1.8.0/design/T03.md
- 変更ファイル（既存）: tests/security.test.ts
- 期待値を変えた既存テスト（全件）:
  - tests/security.test.ts の「v1.7.1 T11: HSTS (N11)…」の it.each の 1 件目（`max-age=15552000; includeSubDomains; preload`）: `expectPreloadInfo` を true → false にし、題名を直した。理由: T03 で SEC-HSTS-03 を「max-age が 1 年以上で includeSubDomains だけが無いとき」に限る仕様に変わったため。SEC-HSTS-02（warning / low）の期待は変えていない
- 判断したこと:
  - HSTS: preload があり 0 < max-age < 1 年なら SEC-HSTS-02 の 1 行だけにし、説明に指示書の文言「preload の登録条件も満たしていない」を含める。重大度は preload の有無で変えない。max-age が 0・未指定で preload がある場合も SEC-HSTS-03 は出さない（1 年以上ではないため）。この場合の説明への文言の追加は任意とした
  - レポートの受け入れ条件は、executeInspection で作ったレポートと Markdown で、HSTS の指摘と表の行がそれぞれ 1 つであり、lintReportPair が合格することで確かめる
  - version-matcher: 既存テストは `1.0.0-nxt` を壊れた字句として扱う（`satisfiesVersionRange('1.5.0', '>= 1.0.0-nxt')` が false、`isValidRange('>= 1.0.0-nxt')` が false）。SemVer 2.0 では `nxt` は正しい識別子なので、すべての場所で書式全般を受け付けると既存テストが落ちる。そこで、観測した版（第 1 引数、compareVersions）は SemVer 2.0 の書式全般を受け付け、DB の range の比較節の版は従来の固定の語の規則のまま（scripts/validate-advisories.mjs の isValidRange と一致させる）とした。検証が拒否する range にはどの版も一致しないことをテストする
  - 既存の表記（`rc1` の語と数字の分解、`-next.0.0.0`）と Linux ディストリビューションの印の扱いは変えない。大文字・小文字の比較（既存は小文字にする）と、数字だけの識別子の先頭の 0 は既存の挙動を保ち、テストでは求めない
- 確認したこと: `npx vitest run tests/hsts-prerelease.test.ts tests/security.test.ts` で 30 件が失敗。理由は機能が無いこと（SEC-HSTS-03 が追加で出て行が 2 つになる、固定の語に無いプレリリースが解析できない）で、テスト自身の誤りではない。既存の版照合テスト（version-check・advisory-db-invariants・review-v1.6.5-acceptance）と test-hygiene は現状で合格。`npx tsc --noEmit` は合格
- 外部の事実:
  - SemVer 2.0.0 §9〜§11（プレリリースとビルドメタデータの書式、順位の規則、例の順序） — https://semver.org/spec/v2.0.0.html（2026-11-11）
  - HSTS preload の登録条件（max-age 31536000 以上、includeSubDomains、preload） — https://hstspreload.org/（2026-11-11）
- 未解決: 「SemVer 2.0 の書式全般」と既存テストの `1.0.0-nxt` の拒否は、上の「観測した版と range の比較節で規則を分ける」解釈で両立させた。DB の range でも書式全般を受け付けたい場合は、既存テストと validate-advisories.mjs の変更を伴うので人の判断が要る

## T03 停止（夜間スクリプトによる自動記録）  (2026-11-11 23:45)
- 理由: 実装の担当が、テストの期待値の変更が必要と判断した: tests/hsts-prerelease.test.ts 250行目の期待値(false)がSemVer仕様(2.1.0-SNAPSHOT < 2.1.0)と矛盾するためneedsTestChangeをtrueに設定しました。
- 変更の退避先: git stash の「v1.8.0 T03 stop 20261111-231822」（記録時点で stash@{0}。番号はずれるので git stash list で名前を確認）。夜間ログのフォルダにパッチもある
- 人間に判断してほしいこと: 設計メモとテストを読み、期待値を変えるべきか判断する。変えるなら人がテストを直してコミットし、RETRY_STOPPED=1 で再実行

## T04 未完了（夜間スクリプトによる自動記録）  (2026-11-12 00:03)
- 理由: 設計の工程が完了しなかった（設計とテストの担当: error）
- 変更の退避先: なし
- 人間に判断してほしいこと: ログを確認し、RETRY_STOPPED=1 で再実行するか、人が設計メモとテストを書く

## T05 未完了（夜間スクリプトによる自動記録）  (2026-11-12 00:18)
- 理由: 設計の工程が完了しなかった（設計とテストの担当: error）
- 変更の退避先: なし
- 人間に判断してほしいこと: ログを確認し、RETRY_STOPPED=1 で再実行するか、人が設計メモとテストを書く

## T03 人の判断  (2026-11-12)
- 実装の担当の needsTestChange を採用。tests/hsts-prerelease.test.ts 250 行目の期待値を true に変更（SemVer §11 の順序と SPEC-11「プレリリースは修正版より前として照合する」に合わせる）

---

## T03 実装  (2026-11-12 01:29)
- 変更ファイル: src/security/headers.ts, src/security/version-matcher.ts, docs/DETECTION_SPECIFICATION.md
- 判断したこと:
  - HSTS:
    - `0 < max-age < 31536000`（および `max-age=0`・未指定）かつ `preload` がある場合、SEC-HSTS-02 の 1 件にまとめ、`description` に「preload の登録条件も満たしていない」旨（`PRELOAD_PHRASE`）を追記した。重大度は既存の区分（86400 未満・0・未指定は medium、86400 以上 1 年未満は low）を維持した。
    - SEC-HSTS-03 は、`hasPreload && maxAge !== null && maxAge >= 31536000 && !hasSubDomains`（max-age が 1 年以上かつ includeSubDomains のみ未指定）の場合にのみ出力するよう条件を限定した。
  - version-matcher:
    - 観測した版（`parseVersion(version)`、`compareVersions`、`satisfiesVersionRange` の第 1 引数）は、SemVer 2.0 §9 の書式全般（`[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*`）を受け付けるよう拡張した。既存の固定の語（`PRERELEASE_RE`）に一致するものは優先して語と数値を分解し、`rc2 < rc10` などの既存の順序規則を保持した。
    - DB の range 比較節の版（`satisfiesSingleClause` の第 2 引数内の対象版）は、`parseVersion(targetVer, { strictPrerelease: true })` として固定の語（`PRERELEASE_RE`）のみを受け付けるようにし、`scripts/validate-advisories.mjs` の `isValidRange` と照合動作を完全に一致させた。
    - ビルドメタデータ（`+...`）は既存の検証および無視処理を維持し、`+sha-…` 付きの版の比較・範囲照合に対応させた。
  - 仕様書 `docs/DETECTION_SPECIFICATION.md` に HSTS の 1 行化とプレリリース・ビルドメタデータの扱いを反映した。
- 外部の事実:
  - SemVer 2.0.0 §9〜§11（プレリリース・ビルドメタデータ・順位規則） — https://semver.org/spec/v2.0.0.html（2026-11-11）
  - HSTS preload の登録条件（max-age 31536000 以上、includeSubDomains、preload） — https://hstspreload.org/（2026-11-11）
- 未解決: なし

---

## T04 設計  (2026-11-12 01:36)
- 変更ファイル（新規）: tests/interstitial.test.ts, docs/dev/v1.8.0/design/T04.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - テストは公開 API（extractDomSignals → executeInspection → generateMarkdownReport / lintReportPair）を通して確かめ、判定の内部関数には依存させない。新しく前提にするのは `InspectionReport.interstitial?: { vendor: 'Cloudflare' | 'AWS WAF' | 'Fastly'; evidence: string[] }` と `src/popup/render.ts` の `renderInterstitialNoticeHtml(info)` だけ
  - 「不完全」: 完全性の値は既存の partial にし、partialReasons に確認画面の理由を足す。「不完全」の語は Markdown とポップアップの注意の文に入れる。表示ラベルは変えない
  - 印はベンダーごとに数える。cf-mitigated は値 challenge、x-amzn-waf-action は値 captcha / challenge のときだけ印にする。ヘッダーは origin が一致した観測済みのものだけを使う
  - /cdn-cgi/challenge-platform/ は普通のページにも挿入されるので 1 つの印にしかならない。Cloudflare のページ内の印は他に一次資料で確かめられず、採用しなかった（Cloudflare は実際にはヘッダーで判定する）
  - 指示書の候補以外の印は採用しなかった
  - 「フィクスチャ」は tests/fixtures の DOM シグナルのフィクスチャとレポートのフィクスチャとした（test-server のページは対象外）
- 確認したこと: `npx vitest run tests/interstitial.test.ts` で 33 件中 17 件が失敗。理由はすべて機能が無いこと（interstitial が無い、完全性が complete のまま、注意が出ない、許可リストにヘッダーが無い、renderInterstitialNoticeHtml が無い）。陰性・互換・lint の 16 件は現状で合格（前提の確認で、テストの文書からタイトルと id が読めることも確かめた）。`npx tsc --noEmit` は合格。test-hygiene と content-script のテストも合格
- 外部の事実:
  - Cloudflare の確認画面には `cf-mitigated: challenge`（唯一の値） — https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/（2026-11-12）
  - Cloudflare の JavaScript Detections は全 HTML ページに `/cdn-cgi/challenge-platform/…` を挿入する — https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/（2026-11-12）
  - AWS WAF の Challenge / CAPTCHA のレスポンスには `x-amzn-waf-action: challenge`（202）/ `captcha`（405） — https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html（2026-11-12）
- 未解決: なし

---

## T04 実装  (2026-11-12 01:48)
- 変更ファイル: src/shared/types.ts, src/detection/interstitial.ts, src/content/content-script.ts, src/background/service-worker.ts, src/export/markdown.ts, src/popup/render.ts, src/popup/popup.ts
- 判断したこと:
  - 型定義（`src/shared/types.ts`）:
    - `InterstitialVendor`（`'Cloudflare' | 'AWS WAF' | 'Fastly'`）と `InterstitialInfo`（`vendor`, `evidence: string[]`）を定義。
    - `DomSignals` に `interstitialMarkers?: string[]` を追加し、`InspectionReport` に `interstitial?: InterstitialInfo` を追加した。
  - 判定ロジック（`src/detection/interstitial.ts`）:
    - レスポンスヘッダー判定（ヘッダー1件で判定）: `cf-mitigated: challenge`（Cloudflare）、`x-amzn-waf-action: captcha / challenge`（AWS WAF）を判定。大文字小文字や前後の空白を無視して照合。
    - ページ内印判定（同一ベンダーで2件以上で判定）: Fastly の印としてタイトル `Client Challenge`、DOM要素ID `id="fastlyLogo"`、`id="captchaTitle"` を対象とし、2件以上該当した場合に Fastly と判定。
    - 異なるベンダーの印を合算しないこと、およびタイトル単体・`/cdn-cgi/challenge-platform/` 単体では判定しない設計ルールを順守。
  - シグナル収集（`src/content/content-script.ts`）:
    - `extractDomSignals` 内で `fastlyLogo` および `captchaTitle` の要素存在を安全に検査し、`interstitialMarkers` に格納した。
  - 調査統括・完全性（`src/background/service-worker.ts`）:
    - `ALLOWED_RESPONSE_HEADERS` に `cf-mitigated` と `x-amzn-waf-action` を追加（G5）。
    - `executeInspection` で `detectInterstitial` を呼び出し、確認画面を検出した場合は `coverage.overallStatus` を `'partial'` に設定し、`coverage.details.partialReasons` に理由を追加。診断処理自体（技術検出・セキュリティ診断）は中断せず継続させた（G6）。
  - レポート出力（`src/export/markdown.ts`）:
    - `report.interstitial` が存在する場合、タイトル部と `## 1. 調査概要` の間に注意ブロック（`> [!WARNING]`）を出力。「確認画面を診断している可能性」、ベンダー名、「不完全」を含む文言を構成した。
  - UI表示（`src/popup/render.ts`, `src/popup/popup.ts`）:
    - `renderInterstitialNoticeHtml` を実装。エスケープ処理を通すことで XSS を防止し、インラインイベントハンドラを使用しない形とした。未検出時は空文字を返却。
    - `popup.ts` の `renderTechnologies` から呼び出してポップアップ一覧の先頭に警告バナーを表示させた。
- 外部の事実:
  - Cloudflare の確認画面には `cf-mitigated: challenge`（唯一の値） — https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/（2026-11-12）
  - Cloudflare の JavaScript Detections は全 HTML ページに `/cdn-cgi/challenge-platform/…` を挿入する — https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/（2026-11-12）
  - AWS WAF の Challenge / CAPTCHA のレスポンスには `x-amzn-waf-action: challenge`（202）/ `captcha`（405） — https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html（2026-11-12）
- 未解決: なし

---

## T05 設計  (2026-11-12 01:55)
- 変更ファイル（新規）: tests/collect-settle.test.ts, docs/dev/v1.8.0/design/T05.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - 判定は scripts/collect-reports.mjs の純粋関数 `judgeSettle(samples, opts)` と、観測・時計・待ちを差し替えられる `waitForSettle(probe, opts)` に分け、どちらもブラウザなしで確かめる
  - URL は `#` 以降を含めて比べる。DOM の変化は MutationObserver の累計の数が前回と違うこと。「URL が止まっている」かつ「DOM が止まっている」が settleMs 以上続けば落ち着いたとする（境界を含む）
  - 上限は最初の観測から数える。上限と落ち着いた条件が同時なら落ち着いたを優先（打ち切りの誤記録を避ける）。観測の例外は失敗にせず変化として扱う
  - 新しい CLI 引数は指示書のとおり `--settle-ms`（既定 1500）だけ。上限は `parseArgs` の戻り値 `settleMaxMs`（既定 15000 を推奨）。`--wait` は変えない
  - _summary.md では、結果の `settle.status` が `timeout` のサイトの行に「待ち打ち切り」を出す。settle の無い従来の結果では出さない
  - test-server は import すると待ち受けを始めるため、`/spa-settle` の経路の有無をソースの文字列で確かめるだけにした。3 回取得して同じになることは人が朝に確かめる
- 確認したこと: `npx vitest run tests/collect-settle.test.ts` で 24 件中 22 件が失敗。理由はすべて機能が無いこと（judgeSettle / waitForSettle が無い、--settle-ms が不明なオプション、settleMs が無い、「待ち打ち切り」が出ない、/spa-settle が無い）。合格の 2 件は陰性（settle の無い行に出ない）と入力エラーの検査。`npx tsc --noEmit` は合格
- 外部の事実:
  - Playwright の page.addInitScript は遷移のたび、ページのスクリプトより前に評価される。waitUntil 'networkidle' は DISCOURAGED — https://playwright.dev/docs/api/class-page（2026-11-12）
- 未解決: 3 回取得して技術の一覧が同じになること（受け入れ条件 1）は人が test-server で確かめる

---

## T05 実装  (2026-11-12 02:02)
- 変更ファイル: scripts/collect-reports.mjs, test-server/server.mjs
- 判断したこと:
  - `judgeSettle(samples, opts)`:
    - 純粋関数として実装し、空観測配列は `waiting` を返却。
    - 直前観測と `url` または `domMutations` が変化した最後の時刻 `lastChangeAt` を追跡し、`stableMs = last.at - lastChangeAt`、`elapsedMs = last.at - first.at` を算出。
    - `stableMs >= opts.settleMs` の場合は上限時刻到達時であっても `settled` を優先判定。
    - それ以外で `elapsedMs >= opts.maxWaitMs` なら `timeout`、いずれでもなければ `waiting` を返却。
  - `waitForSettle(probe, opts)`:
    - 開始時刻からの経過を `now()` で測定。
    - `probe` の評価時に例外（コンテキスト破棄など）が発生した場合、前回と異なる番兵観測データ（`__error_${++errorSeq}`, domMutations: -1）を記録して変化として継続待機。
    - `judgeSettle` が `settled` または `timeout` を返した時点でループを抜け、`waitedMs = now() - startAt` を返却。
  - `parseArgs`:
    - `opts.settleMs`（既定 1500）と `opts.settleMaxMs`（既定 15000）を追加。
    - CLI 引数 `--settle-ms <ms>` のパースと、0以上の有限数値かどうかのバリデーション（負数・非数値・引数不足時に例外送出）を実装。
  - `inspectOne` / `main`:
    - `page.addInitScript` により MutationObserver（`childList`, `subtree`, `characterData`）をあらかじめ注入し、変化数を `window.__wiSettleMutations` に蓄積。
    - `load` および `networkidle` の待機後、`waitForSettle` を実行。`status === 'timeout'` の場合は `notes` に「待ち打ち切り」を追加。
    - 取得結果オブジェクトに `settle: { status, waitedMs }` を格納。
  - `buildSummary`:
    - `r.settle?.status === 'timeout'` の行の備考列に「待ち打ち切り」を追加（すでに notes に存在する場合の重複を防止）。
  - `test-server/server.mjs`:
    - `/spa-settle` ルートを追加。初期表示から 300ms 後に `location.hash = '#/'` に遷移し、さらに 900ms 後に jQuery 3.6.0 の定義、Bootstrap 4.3.1 の link 要素および DOM 要素を描画する SPA ページを実装。
    - ナビゲーションメニューおよび起動ログに `/spa-settle` を追加。
- 外部の事実:
  - Playwright の `page.addInitScript` はページ遷移のたび、ページスクリプト実行前に評価される — https://playwright.dev/docs/api/class-page（2026-11-12）
- 未解決:
  - 受け入れ条件 1（test-server の /spa-settle を 3 回取得して技術の一覧が同じであること）は、ブラウザとサーバーを起動して人が朝に確認する。

---

## T06 設計  (2026-11-12 06:06)
- 変更ファイル（新規）: tests/header-extras.test.ts, docs/dev/v1.8.0/design/T06.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - 8 つの ID はすべて既存の `checkHttpHeaders(headers, url, isHttps)` の結果で確かめる。新しい公開 API は必須にしない（Permissions-Policy の解析関数 `parsePermissionsPolicy` は推奨の名前だけ設計メモに書いた）
  - SEC-COOP-01 は「無い」「unsafe-none」に加え、仕様にない値（ブラウザは無視して unsafe-none 扱い）でも info で出す。指摘は info だけなので警告は増えない
  - SEC-PERM-02 の強い権限は、指示書に名前がある camera・microphone・geolocation・payment・usb の 5 つだけにする（「など」を広げない。安全側）。複数あっても 1 件にまとめ、根拠に権限名をすべて書く。`*` はトークンか Inner List の要素のとき（文字列の中の `*` は数えない）
  - SEC-PERM-03 は RFC 9651 の Dictionary として解析できないとき。解析できないときは SEC-PERM-02 を出さない（ブラウザがヘッダー全体を無視するので断定しない）
  - COEP は、無いときは何も出さない（指示書「既定で推奨しない」）。CORP は大文字・小文字を区別し、引数も認めない（Fetch の ABNF）
  - X-XSS-Protection の `0` と未設定は出さない。`1` で始まらない解釈できない値も出さない
  - 新しい接頭辞 SEC-COOP- / SEC-COEP- / SEC-CORP- / SEC-XXSS- を `HEADER_DEPENDENT_CHECK_PREFIXES` に足す（SEC-PERM- と SEC-DISC- は既にある）。未観測のとき、キャッシュなしでも origin 違いでも unknown・要確認 0 になることを確かめる
  - G5 のうち T06 で使う x-xss-protection・server-timing・x-aspnetmvc-version を、取得するヘッダーに足すことも確かめる
  - 指示書 §5「仕様書のカタログに出ること」: `npm run spec:generate` が作り直すのは §3（技術のカタログ）と README の表だけで、セキュリティの ID は出さない。そのため「`docs/DETECTION_SPECIFICATION.md` に 8 つの ID がある」で確かめる（§8.3 に手で書く）
- 確認したこと: `npx vitest run tests/header-extras.test.ts` で 97 件中 49 件が失敗。理由はすべて機能が無いこと（新しい ID が出ない、接頭辞が無い、3 つのヘッダーが取得の対象に無い、仕様書に ID が無い）。合格の 48 件は陰性のケースと、今の整合性チェッカーの確認。`npx tsc --noEmit` は合格
- 外部の事実（詳細は設計メモ）:
  - COOP・COEP の値と無効な値の扱い — https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies（2026-11-12）
  - CORP の ABNF（大文字・小文字を区別） — https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header（2026-11-12）
  - Permissions-Policy の `*`（トークンか、`*` を含むリスト） — https://w3c.github.io/webappsec-permissions-policy/（2026-11-12）
  - Structured Field の Dictionary の解析 — https://www.rfc-editor.org/rfc/rfc9651.html §4.2（2026-11-12）
  - X-XSS-Protection・X-AspNetMvc-Version — https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html（2026-11-12）
- 未解決:
  - Server-Timing を指摘する根拠の一次資料は未確認（指示書の判断のとおり info にとどめる）
  - PRIVACY_POLICY に足す取得ヘッダーの文面は、人が承認する（G5）
  - SEC-COOP-01 は COOP の無いページのほとんどで INFO が 1 件増える（要確認件数は増えない）

---

## T06 実装  (2026-11-12 06:21)
- 変更ファイル: src/security/headers.ts, src/background/service-worker.ts, docs/DETECTION_SPECIFICATION.md
- 判断したこと:
  - `src/security/headers.ts`:
    - `SECURITY_HEADER_NAMES` に `'x-aspnetmvc-version'`, `'x-xss-protection'`, `'server-timing'` を追加（これにより `service-worker.ts` の `ALLOWED_RESPONSE_HEADERS` にも自動反映）
    - Permissions-Policy の解析関数 `parsePermissionsPolicy` および型 `PermissionsPolicyAllowlist` を RFC 9651 Dictionary に準拠して実装。構文エラー時（Feature-Policy 記法、末尾カンマ、連続カンマ、閉じない括弧等）は null を返し、`SEC-PERM-03`（info / info）を発火。正常パース時は強い権限 5 つ（camera, microphone, geolocation, payment, usb）のいずれかがトークン `*` または Inner List 内の `*` を持つ場合に 1 件に集約して `SEC-PERM-02`（warning / low）を発火（項目名は両者とも `Permissions-Policy` で統一）
    - Inner List 内のアイテム間区切り（SP）の解析処理において、アイテム直後の空白文字・閉じ括弧の判定順序を修正し、`camera=(self "https://cdn.example.test")` などの複数アイテムを持つ Inner List が正しく解析されるように対応
    - Cross-Origin 系ヘッダーの評価:
      - COOP (`SEC-COOP-01`): 未設定、`unsafe-none`、または仕様外の値を info / info で指摘。`same-origin`, `same-origin-allow-popups`, `noopener-allow-popups` を有効値として許容
      - COEP (`SEC-COEP-01`): 既定では推奨せず、ヘッダーが存在し仕様値（`require-corp`, `credentialless`, `unsafe-none`）以外の場合のみ info / info で指摘
      - CORP (`SEC-CORP-01`): ヘッダーが存在し仕様値（`same-origin`, `same-site`, `cross-origin`）以外の場合に info / info で指摘（引数なし・大文字小文字区別）
    - X-XSS-Protection (`SEC-XXSS-01`): ヘッダー値の主部が `1` の場合のみ info / info で指摘（`0` または未設定は非指摘）
    - 情報露出: `X-AspNetMvc-Version` が存在する場合に `SEC-DISC-04`（warning / low）、`Server-Timing` が存在する場合に `SEC-DISC-05`（info / info）を `information-disclosure` カテゴリで指摘
  - `src/background/service-worker.ts`:
    - `HEADER_DEPENDENT_CHECK_PREFIXES` に `'SEC-COOP-'`, `'SEC-COEP-'`, `'SEC-CORP-'`, `'SEC-XXSS-'` を追加（ヘッダー未観測時の unknown 化および要確認件数 0 を保証）
  - `docs/DETECTION_SPECIFICATION.md`:
    - §8.3 に 8 つの ID（SEC-COOP-01, SEC-COEP-01, SEC-CORP-01, SEC-XXSS-01, SEC-PERM-02, SEC-PERM-03, SEC-DISC-04, SEC-DISC-05）の判定基準・status・重大度を手動で追記
- 外部の事実（設計メモを引用）:
  - COOP・COEP の値と無効な値の扱い — https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies（2026-11-12）
  - CORP の ABNF（大文字・小文字を区別） — https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header（2026-11-12）
  - Permissions-Policy の `*`（トークンか、`*` を含むリスト） — https://w3c.github.io/webappsec-permissions-policy/（2026-11-12）
  - Structured Field の Dictionary の解析 — https://www.rfc-editor.org/rfc/rfc9651.html §4.2（2026-11-12）
  - X-XSS-Protection・X-AspNetMvc-Version — https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html（2026-11-12）
- 未解決: なし

---

## T07 設計  (2026-11-12 06:34)
- 変更ファイル（新規）: tests/csp-extras.test.ts, docs/dev/v1.8.0/design/T07.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - 4 項目は新しい ID `SEC-CSPX-TT-01`（info）・`SEC-CSPX-UIR-01`（info）・`SEC-CSPX-FORM-01`（warning / low）・`SEC-CSPX-REPORT-01`（info）にする。接頭辞を `SEC-CSP-` にしないのは、既存の SEC-CSP-00 / SEC-CSP-03 の集計、SW の CSP の置き換え、SPEC-01 の meta の例外、csp-parser.test.ts の件数の期待値に巻き込まないため。`SEC-CSPX-` を `HEADER_DEPENDENT_CHECK_PREFIXES` に足す
  - 新しい指摘は `analyzeCSPPolicies` の結果・指摘に入れない。csp-parser.test.ts には form-action や Trusted Types の無い CSP で SEC-CSP-00（合格）や要約の文字列の完全一致を期待するテストが多いため（受け入れ条件 3）
  - 評価は新しい `src/security/csp-extras.ts` の `checkCspExtras(policies, url, context)` と `evaluateCspExtraIssues(policy, allPolicies, context)`。csp-parser.ts は `evaluatePolicyIssuesWithIntersection` に 4 番目の任意の引数（文脈）を足すだけにする（30 行以内）
  - 複数の CSP: TT・UIR・FORM は、どれか 1 つの強制ポリシー（ヘッダーか meta）が指定していれば「ある」。Report-Only の指定は数えない（UIR は仕様上 Report-Only では無視される）
  - UIR は、CSP がまったく無いページでも、混在コンテンツがあれば出す。指示書の表で、この項目だけ「強制の CSP があり」と書かれていないため。info なので警告は増えない
  - REPORT は、ヘッダーのポリシー（強制と Report-Only）の report-to のグループが Reporting-Endpoints の Dictionary のキーに無いとき。積集合は当てはまらない（防御の能力ではなく、レポートが届くかの確認のため）。meta のポリシーの report-to は対象にせず、既存の CSP-META-INVALID-REPORT-TO を残す
  - 問題点の表（Markdown 第 8 節）には、文脈が渡されたときだけ足し、重大度と内容は診断の項目と同じ文字列にする。ヘッダー未観測のときは文脈を保存せず、表に新しい行を出さない（診断の項目が unknown なのに表で指摘すると矛盾するため）。文脈の無い古いレポートでは、既存のテストどおり「問題点はありません」のまま
  - G5 のうち T07 で使う reporting-endpoints を、取得するヘッダーに足すことを確かめる
  - 受け入れ条件 2・3（差分の行数）は、起点 `a5bd583` からの `git diff --numstat` で確かめる。CI の浅い clone で起点が無いときは、起点の行数（1113 行）＋30 行以下と、既存の代表的な期待値の文字列で代わりに確かめる
- 確認したこと: `npx vitest run tests/csp-extras.test.ts` は、新しいモジュールが無いためファイルの読み込みで失敗（機能が無いことが理由）。`npx tsc --noEmit` のエラーも、新しいモジュールが無いことと、`evaluatePolicyIssuesWithIntersection` の 4 番目の引数がまだ無いことだけ。作業用の参照実装（コミットしない）で csp-extras だけを差し替えると 92 件中 74 件が合格し、4 項目の単一・複数・meta のケースはすべて合格した。残る 18 件は未実装の接続部分（表、SW、接頭辞、G5、Markdown、仕様書）が原因
- 外部の事実（詳細は設計メモ）:
  - meta の CSP で無効なのは report-uri・frame-ancestors・sandbox と Report-Only — https://w3c.github.io/webappsec-csp/#meta-element（2026-11-12）
  - upgrade-insecure-requests は Report-Only では無視される — https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery（2026-11-12）
  - default-src のフォールバックはフェッチ用のディレクティブだけ（form-action は Navigation Directives） — https://w3c.github.io/webappsec-csp/#directive-default-src（2026-11-12）
  - Reporting-Endpoints は Dictionary の Structured Field、値は文字列 — https://w3c.github.io/reporting/#header（2026-11-12）
  - Chrome の Reporting-Endpoints と Report-To の使い分け — https://developer.chrome.com/blog/reporting-api-migration（2026-11-12）
  - require-trusted-types-for と 'script' — https://w3c.github.io/trusted-types/dist/spec/（2026-11-12）
- 未解決:
  - 旧式の Report-To ヘッダーだけで定義したグループを、新しい Chrome が CSP の report-to に使うかは未確認。表どおり Reporting-Endpoints だけを見る（info）
  - require-trusted-types-for の ABNF の原文は未確認。`'script'` の大文字・小文字の扱いはテストしない
  - SEC-CSPX-FORM-01（low）は、form-action の無い CSP のページで要確認が 1 件増える（指示書の表のとおり）
  - PRIVACY_POLICY に reporting-endpoints を足す場合の文面は、人が承認する（G5）

---

## T07 実装  (2026-11-12 06:48)
- 変更ファイル: src/security/csp-extras.ts, src/security/csp-parser.ts, src/background/service-worker.ts, src/security/headers.ts, src/shared/types.ts, src/export/markdown.ts, docs/DETECTION_SPECIFICATION.md
- 判断したこと:
  - `src/security/csp-extras.ts` を新規作成し、4 つのチェック項目（`SEC-CSPX-TT-01`, `SEC-CSPX-UIR-01`, `SEC-CSPX-FORM-01`, `SEC-CSPX-REPORT-01`）の評価関数 `checkCspExtras`、ポリシー別問題点表用指摘関数 `evaluateCspExtraIssues`、および Reporting-Endpoints ヘッダー解析関数 `parseReportingEndpoints` を実装した
  - `src/security/csp-parser.ts` では `evaluatePolicyIssuesWithIntersection` に任意の第 4 引数 `extrasContext?: CspExtrasContext` を追加し、既存の積集合評価や SEC-CSP-00 / SEC-CSP-03 集計には一切干渉せず、変更行数を 11 行（追加 8 / 削除 3）にとどめた（30 行以内制限を遵守）
  - `src/background/service-worker.ts` では `HEADER_DEPENDENT_CHECK_PREFIXES` に `'SEC-CSPX-'` を追加し、CSP 解析直後に `checkCspExtras` を呼び出して診断結果に追加するようにした。また `headersObserved` のときのみ `report.cspExtrasContext` を保存し、ヘッダー未観測時は Markdown 表に新しい指摘が出ないようにした
  - `src/security/headers.ts` の `SECURITY_HEADER_NAMES` に `'reporting-endpoints'` を追加し、`ALLOWED_RESPONSE_HEADERS` 経由で取得・サニタイズ保持されるようにした（G5）
  - `src/export/markdown.ts` の第 8 節で `evaluatePolicyIssuesWithIntersection` に `report.cspExtrasContext` を渡し、診断項目と同一の重大度・内容で問題点表に出力するようにした
  - `docs/DETECTION_SPECIFICATION.md` の §8.2 末尾に 4 つのチェック ID の判定・status・重大度を記載した
- 外部の事実（設計メモ T07 より引用）:
  - meta の CSP で無効なのは report-uri・frame-ancestors・sandbox と Report-Only — https://w3c.github.io/webappsec-csp/#meta-element（2026-11-12）
  - upgrade-insecure-requests は Report-Only では無視される — https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery（2026-11-12）
  - default-src のフォールバックはフェッチ用のディレクティブだけ（form-action は Navigation Directives） — https://w3c.github.io/webappsec-csp/#directive-default-src（2026-11-12）
  - Reporting-Endpoints は Dictionary の Structured Field、値は文字列 — https://w3c.github.io/reporting/#header（2026-11-12）
  - require-trusted-types-for と 'script' — https://w3c.github.io/trusted-types/dist/spec/（2026-11-12）
- 未解決:
  - 設計メモに記載のとおり、旧式の Report-To ヘッダーのみで定義されたグループの扱いは対象外とし、Reporting-Endpoints のみを評価対象としている（指摘は info）

---

## T08 設計  (2026-11-12 13:33)
- 変更ファイル（新規）: tests/sri-cache-cookie.test.ts, docs/dev/v1.8.0/design/T08.md
- 期待値を変えた既存テスト: なし
- 判断したこと:
  - content-script は `DomSignals.sriResources?: { kind: 'script' | 'stylesheet'; url; hasIntegrity }[]` を返す。integrity の値は集めない。レポートには `sriResources` を入れない
  - SRI-01 / SRI-02 は `determinePartyType`（PSL）で third-party のものだけ。同一サイト（cdn.example.test と www.example.test、co.jp の同じ登録ドメイン）は対象外。URL は最大 10 件で 1 行、同じ URL は 1 回、クエリとフラグメントは除く（IMPL-07 と同じ）
  - SRI はヘッダーに依存しないので接頭辞を足さない。`SEC-CACHE-` だけを `HEADER_DEPENDENT_CHECK_PREFIXES` に足す。cache-control を取得するヘッダーに足す（G5）
  - 「認証系」は `classifyCookieAdvanced(name).category === 'authentication'`（既存の分類。CSRF は対象外）
  - SEC-CACHE-01 は Cache-Control が無いときも出す。ディレクティブは大文字・小文字を区別せず、`no-store` と完全一致で比べる
  - SEC-COOKIE-EXPIRY の「1 年」は 365 日で、ちょうど 365 日は出さない（「超える」）。セッション Cookie と、expirationDate が無いものは出さない
  - SEC-COOKIE-SAMESITE-NONE は Secure ありだけ（D7）。Partitioned は分けない
  - 新しい ID は、1 ページにつき各 1 件にまとめる（警告を増やしすぎない）
- SEC-SRI-02 の配信元一覧と採用した理由（一次資料。2026-11-12 確認）:
  - `www.googletagmanager.com` — タグマネージャー。公開のたびにサイトで動くコンテナが変わる — https://support.google.com/tagmanager/answer/6107163 、ホスト名は https://developers.google.com/tag-platform/security/guides/csp
  - `js.stripe.com` — 「always be loaded directly from https://js.stripe.com, rather than included in a bundle or hosted yourself」 — https://docs.stripe.com/js/including
  - `www.paypal.com`（path `/sdk/js`） — 「Load the JavaScript SDK directly from https://www.paypal.com/sdk/js. Don't include it in a bundle or host it yourself」、互換のある変更は自動で反映 — https://developer.paypal.com/sdk/js/configuration/
  - `accounts.google.com`（path `/gsi/`） — 「self-hosting or using an offline copy is not a supported use case」、更新が自動で反映 — https://developers.google.com/identity/gsi/web/guides/client-library
  - 採用しなかった: Apple Pay JS SDK（自動更新版での SRI を勧めない旨の回答は https://developer.apple.com/forums/thread/821972 にあるが、配信元のホスト名を一次資料で確認できなかった）
- そのほかの外部の事実（詳細は設計メモ）:
  - RFC 9111 §3（no-store があれば保存しない）・§4（no-cache は保存を禁じない） — https://www.rfc-editor.org/rfc/rfc9111.html（2026-11-12）
  - chrome.cookies の expirationDate は秒、no_restriction は SameSite=None — https://developer.chrome.com/docs/extensions/reference/api/cookies（2026-11-12）
  - 空の integrity は検証しない — https://w3c.github.io/webappsec-subresource-integrity/（2026-11-12）
- 確認したこと: `npx vitest run tests/sri-cache-cookie.test.ts` は 65 件中 36 件が失敗。すべて AssertionError で、機能が無いこと（sriResources が無い、新しい ID が出ない、接頭辞・許可リスト・仕様書に無い）が理由。合格の 29 件は陰性のケース。`npx tsc --noEmit` は合格
- 未解決:
  - RFC 9111 §5.2（ディレクティブ名の大文字・小文字）は原文を確認できなかった。区別しない比較は警告を減らす向きなので採用
  - SEC-CACHE-01（low）は、認証系 Cookie があり no-store の無いページで要確認が 1 件増える（指示書の表のとおり）
  - PRIVACY_POLICY に cache-control と「integrity 属性の有無の確認（値は集めない）」を足す場合の文面は、人が承認する（G5）

---

## T08 実装  (2026-11-12 13:46)
- 変更ファイル: src/shared/types.ts, src/content/content-script.ts, src/security/sri.ts, src/security/cookies.ts, src/security/headers.ts, src/security/engine.ts, src/background/service-worker.ts, docs/DETECTION_SPECIFICATION.md, PRIVACY_POLICY.md
- 判断したこと:
  - `src/shared/types.ts` に `SriResourceItem` インターフェースを定義し、`DomSignals` に任意のフィールド `sriResources?: SriResourceItem[]` を追加した。`InspectionReport` には含めず、DOM 生データがレポートや保存領域に漏洩しないようにした
  - `src/content/content-script.ts` の `extractDomSignals` に `sri` ステップを追加し、`script[src]` および `rel` に `stylesheet` を含む `link[href]` から絶対 URL と `hasIntegrity`（boolean のみ）を最大 200 件収集するようにした。`noscript` / `template` 内の要素は除外し、integrity の属性値は一切変数に保持せず戻り値にも含めないようにした
  - `src/security/sri.ts` を新規作成し、`checkSubresourceIntegrity` および `isSriUnsupportedProvider` を実装した。入力検証を行い、`hasIntegrity === false` かつ PSL による `determinePartyType === 'third-party'` のリソースを対象とした。`stripUrlQueryAndFragment` で URL のクエリ・フラグメントを除去し、自動更新配信元（GTM, Stripe, PayPal, Google Identity）は `SEC-SRI-02`（`info` / `info`）、一般サードパーティは `SEC-SRI-01`（`warning` / `low`）に排他分類した。同一 URL は 1 回のみ計上し、最大 10 件まで観測値に列挙（11 件以上は「他 N 件」）した
  - `src/security/cookies.ts` の `checkCookies` に、認証系 Cookie（`classifyCookieAdvanced(name).category === 'authentication'`）を対象とする有効期限チェック（`SEC-COOKIE-EXPIRY` / 365日超過で `warning`・`low`）と SameSite チェック（`SEC-COOKIE-SAMESITE-NONE` / `normalizeSameSite === 'none'` かつ `secure === true` で `warning`・`low`）を追加した。複数件ある場合も 1 件に集約し、観測値に対象 Cookie 名を表示した
  - `src/security/headers.ts` の `SECURITY_HEADER_NAMES` に `'cache-control'` を追加し（G5）、認証ページのキャッシュ診断関数 `checkAuthPageCacheControl` を実装した。認証系 Cookie が存在し、`Cache-Control` ヘッダーに `no-store` ディレクティブ（大文字小文字不問・完全一致）が含まれない場合に `SEC-CACHE-01`（`warning` / `low`）を出力するようにした
  - `src/security/engine.ts` の `SecurityEngine.evaluate` で `checkSubresourceIntegrity` および `checkAuthPageCacheControl` を呼び出し、診断結果配列に追加した
  - `src/background/service-worker.ts` の `HEADER_DEPENDENT_CHECK_PREFIXES` に `'SEC-CACHE-'` のみを追加した（`SEC-SRI-` や `SEC-COOKIE-` は追加せず、ヘッダー未観測時でも DOM/Cookie 診断結果が維持されるようにした）
  - `docs/DETECTION_SPECIFICATION.md` の §8.3（SRI・Cache-Control）および §8.4（Cookie）に 5 つの ID（`SEC-SRI-01`, `SEC-SRI-02`, `SEC-CACHE-01`, `SEC-COOKIE-EXPIRY`, `SEC-COOKIE-SAMESITE-NONE`）の仕様・判定基準・重大度を手動で追記した
  - `PRIVACY_POLICY.md` に、キャッシュ診断のための `Cache-Control` 取得と、SRI 診断のためのスクリプト・スタイルシートの URL および integrity 属性の有無の確認（値そのものは一切取得・保持しない旨）を日英両表記で追記した
- 外部の事実（設計メモ T08 より引用）:
  - Google タグマネージャー（`www.googletagmanager.com`）: 公開のたびに動くコンテナが変わる — https://support.google.com/tagmanager/answer/6107163 、ホスト名 https://developers.google.com/tag-platform/security/guides/csp （2026-11-12 確認）
  - Stripe.js（`js.stripe.com`）: 直接読み込み推奨、バンドル・自前ホスト非推奨 — https://docs.stripe.com/js/including （2026-11-12 確認）
  - PayPal JavaScript SDK（`www.paypal.com/sdk/js`）: 直接読み込み推奨、自動更新 — https://developer.paypal.com/sdk/js/configuration/ （2026-11-12 確認）
  - Google Identity Services（`accounts.google.com/gsi/`）: 自前ホスト非対応、自動更新 — https://developers.google.com/identity/gsi/web/guides/client-library （2026-11-12 確認）
  - Cache-Control: RFC 9111 §3（no-store があれば保存しない）・§4（no-cache は保存を禁じない） — https://www.rfc-editor.org/rfc/rfc9111.html （2026-11-12 確認）
  - chrome.cookies: expirationDate は秒、no_restriction は SameSite=None — https://developer.chrome.com/docs/extensions/reference/api/cookies （2026-11-12 確認）
  - SRI integrity 属性: 空の integrity は検証しない — https://w3c.github.io/webappsec-subresource-integrity/ （2026-11-12 確認）
- 未解決:
  - PRIVACY_POLICY.md の文面変更（Cache-Control および SRI integrity 属性有無の受動的確認）は、人の承認を前提とする（G5）

---

## T09 設計  (2026-11-12 13:52)
- 変更ファイル: docs/dev/v1.8.0/design/T09.md、tests/release-docs.test.ts（新規）
- 判断したこと:
  - テストに版を書けないため、目標の版（1.8.0）は総合チェック C12 に任せ、テストは「各所の版の表記が package.json の版と一致すること」を見る。既存の spec-integrity.test.ts（lock・manifest・RULES_VERSION・HTML・README バッジ・仕様書の対象バージョン）は変えず、足りない部分を足した
    - 予備の文字列: 既存のテストは 1.6.x・1.7.0 しか見ないため、5 ファイル（service-worker.ts・popup.ts・dashboard.ts・markdown.ts・csv.ts）の版らしいリテラルがすべて package.json の版であることを足した。日付の予備の値は対象外
    - バッジ: 要素（brandVersion・dashboardVersion）の中身が `v<版>` と完全一致
    - README: 「機能一覧」の見出しの版（保守ガイド §1.2 No.9）。本文の内容は指示書が指定していないので縛らない
  - PRIVACY_POLICY: G5 の 8 つのヘッダー名が許可リストにあり、PP に書かれていること。Set-Cookie を保持しない記述と、integrity 属性の有無だけを見る（値は取得しない）記述が英日で残ること
  - G5 の `report-to` が `ALLOWED_RESPONSE_HEADERS` に無い（T07 では「任意」とされた）。G5 は決定済みの事項なので、`SECURITY_HEADER_NAMES` に足すことを実装の方針に書き、テストで求める。どのチェックも読まないので警告は増えない
  - MAINTENANCE_GUIDE: test-hygiene・固定 DB・readPackageVersion（テストの書き方）、rehearse-db-release.mjs（予行）、check-size.mjs と 2 MB・3 MB（G7）の記述
  - 総合チェック FAIL 0・完了報告書・check-result.json は完了報告書の工程で作るため、Vitest では確かめない
- 確認したこと: `npx vitest run tests/release-docs.test.ts` は 23 件中 10 件が失敗（PP に G5 のヘッダー名が無い 6 件、report-to が許可リストに無い 1 件、保守ガイドの記述が無い 3 件）。版の一致のテストは、版上げ前の現在の版同士で一致しているため合格する（expectRed は false）。`tests/test-hygiene.test.ts` と `npx tsc --noEmit` は合格
- 外部の事実: なし
- 期待値を変えた既存テスト: なし
- 未解決:
  - PRIVACY_POLICY の文面（G5 のヘッダーの追加）は人が承認する
  - `report-to` を許可リストに足す判断（G5 に従った。T07 の「任意」との違い）は、朝の確認で人が見る


## T09 停止（夜間スクリプトによる自動記録）  (2026-11-12 14:03)
- 理由: 実装の担当が、テストの期待値の変更が必要と判断した: tests/advisory-pipeline.test.mjs:444の'1.8.0'がtest-hygieneに抵触。tests/は変更禁止のためテスト側の修正が必要です。
- 変更の退避先: git stash の「v1.8.0 T09 stop 20261112-132316」（記録時点で stash@{0}。番号はずれるので git stash list で名前を確認）。夜間ログのフォルダにパッチもある
- 人間に判断してほしいこと: 設計メモとテストを読み、期待値を変えるべきか判断する。変えるなら人がテストを直してコミットし、RETRY_STOPPED=1 で再実行

## T09 人の判断  (2026-11-12)
- 実装の担当の needsTestChange を採用。tests/advisory-pipeline.test.mjs 444 行目（minExtensionVersion の変更を major と判定するテストの合成データ）の '1.8.0' が新しい版と重なり test-hygiene に当たるため、'1.8.9' に変更（判定の結果は変わらない。v1.7.0 T16 で入った値）

---

## T09 実装  (2026-11-12 16:55)
- 変更ファイル:
  - package.json, package-lock.json, public/manifest.json, src/detection/rules/index.ts
  - src/background/service-worker.ts, src/popup/popup.ts, src/dashboard/dashboard.ts, src/export/markdown.ts, src/export/csv.ts
  - popup.html, dashboard.html
  - src/security/headers.ts
  - docs/DETECTION_SPECIFICATION.md
  - README.md
  - PRIVACY_POLICY.md
  - docs/MAINTENANCE_GUIDE.md
- 判断したこと:
  - 版の統一（1.8.0）: package.json, package-lock.json（自パッケージ2か所のみ）, public/manifest.json, src/detection/rules/index.ts（RULES_VERSION）をすべて 1.8.0 に更新した
  - フォールバック文字列・HTML バッジ: service-worker.ts, popup.ts, dashboard.ts, markdown.ts, csv.ts の版フォールバック文字列を '1.8.0' に更新し、popup.html, dashboard.html の初期バッジテキストを 'v1.8.0' に更新した
  - G5 レスポンスヘッダー許可リスト: src/security/headers.ts の SECURITY_HEADER_NAMES に 'report-to' を追加し、ALLOWED_RESPONSE_HEADERS に G5 で指定された 8 つのヘッダー（x-xss-protection, cache-control, server-timing, x-aspnetmvc-version, reporting-endpoints, report-to, cf-mitigated, x-amzn-waf-action）がすべて含まれるようにした
  - PRIVACY_POLICY.md: 英語および日本語の両セクションに、G5 の 8 つのヘッダーの取得目的を明記した。レビュー指摘に基づき、X-XSS-Protection のチェック ID を `SEC-XXSS-01` に修正し、Server-Timing の用途を実装に合わせて内部処理情報の露出診断（`SEC-DISC-05`）に修正した。Set-Cookie の完全除外および SRI の integrity 属性有無のみ取得・値非保持の文面を維持した
  - docs/MAINTENANCE_GUIDE.md: §5 を新設し、テスト作成規約（版・件数の直接記述禁止、固定 DB tests/fixtures/advisory-db.fixture.json の使用、readPackageVersion、tests/test-hygiene.test.ts による検査）、サイズ上限（scripts/ci/check-size.mjs、advisory-db.json 2 MB / dist 3 MB）を追記した。レビュー指摘に基づき、§5.2 の CI ジョブ名を `db-release-rehearsal` に修正し、予行スクリプトの動作説明（一時コピーで manifest の 4 つ目の数字を採番、dataVersion 更新、テスト実行を行い元の作業ツリーは変更しない）を正確な内容に修正した
  - README.md: バッジおよび機能一覧見出し・目次リンクを v1.8.0 に更新し、機能一覧表に v1.8.0 の主要変更を追記した。レビュー指摘に基づき、NEW-03 の行で CSP 追加項目を Trusted Types、upgrade-insecure-requests、form-action、Reporting-Endpoints の 4 項目に修正し、Cookie の説明を認証系 Cookie の属性診断（SameSite=None・過大な有効期限の指摘）に修正した
  - docs/DETECTION_SPECIFICATION.md: 対象バージョンを v1.8.0 に更新した
- 外部の事実: なし（指示書および設計メモに基づく）
- 未解決:
  - PRIVACY_POLICY.md の文面変更（G5 の 8 ヘッダー追加）は、人が承認する（完了報告書に記載）

---

## 報告書作成  (2026-11-12 17:05)
- 変更ファイル: docs/dev/v1.8.0/COMPLETION_REPORT.md, docs/dev/v1.8.0/WORKLOG.md
- 判断したこと:
  - REPORT_TEMPLATE.md に従い、REPORT_DATA.json、check-result.json、kit-summary.json、各タスクの設計メモおよび WORKLOG.md からすべての必要情報を漏れなく転記し COMPLETION_REPORT.md を作成した
  - テスト件数は passed 1083 / skipped 0 / failed 0、TODO(報告書) はすべて解消した
  - 外部の事実の一次資料と確認日、PRIVACY_POLICY の承認必要事項、人間の確認事項を整理して記載した
- 未解決: なし



