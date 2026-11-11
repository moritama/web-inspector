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
