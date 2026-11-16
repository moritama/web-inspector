# v1.8.1 完了報告書

## 1. サマリー

- 作業期間: 2026-11-14 〜 2026-11-16
- ブランチ / 最終コミット: `feature/v1.8.1` / `6cfd5f1`（起点は main の `0e891fa`）
- 結果: 完了 8 件 / 一部完了 0 件 / 停止・未完了 0 件（夜間キットのタスク 8 件。T00 は人の作業）
- 総合チェック（`node scripts/dev/check-v1.8.1.mjs`）: 26 項目中 25 件 PASS / 0 件 WARN / 1 件 FAIL（未作成だった C14 は本報告書の作成で解消、スクリプトが再チェック）
- 実施体制: 夜間（無人）モードで実施。設計とテスト・差分のレビューと、実装を、別々の AI コーディングエージェントが担当。変更範囲の確認・テスト・DB の再生成・外部データの取得・コミットは夜間スクリプトが実行。
- 一言で: OS リリース推定と EOL 判定、Debian / Ubuntu の OSV 脆弱性情報照合（NEW-04 第2・第3段階）および HTTPS 専用ヘッダー（COOP/COEP）の「対象外」判定を実装し、全 1684 件のテストと総合チェックを通過。

## 2. 実行環境

| 項目 | 値 |
| --- | --- |
| OS | macOS 27.2.1 |
| Node.js / npm | v24.13.0 / 11.6.2 |
| 実装の担当 / モデル | AI コーディングエージェント CLI 1.5.9 / Gemini 3.8 Flash (High)（レビュー: Gemini 4 Argon (High)） |
| 設計・レビューの担当 / モデル | AI コーディングエージェント CLI 2.1.311 / 既定（未指定） |

## 3. タスク別結果

| ID | 内容 | 結果 | 実装のコミット | 実装の試行 / retry | 所要（分） | テストレビューの指摘（採用 / 却下） | 期待値を変えた既存テスト | 備考 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | dpkg の版比較 | 完了 | 9406352 | 1 / 0 | 13 | 指摘 0 件（0 / 0） | なし | - |
| T02 | OS のライフサイクル表と対応表、DB への組み込み | 完了 | 35aeb58 | 2 / 1 | 504 | 指摘 0 件（0 / 0） | tests/advisory-pipeline.test.mjs, tests/advisory-db-invariants.test.ts, tests/fixtures/advisory-db.fixture.json | データ取得 |
| T03 | OS リリースの推定と EOL 判定 | 完了 | 5c685df | 3 / 2 | 40 | 指摘 0 件（0 / 0） | なし | - |
| T04 | 対応表の週次の突き合わせ | 完了 | b61e8cd | 1 / 0 | 22 | 指摘 0 件（0 / 0） | なし | - |
| T05 | OSV の Debian / Ubuntu データの取り込み | 完了 | 6cf9619 | 1 / 0 | 31 | 指摘 0 件（0 / 0） | なし | データ取得 |
| T06 | CVE ごとの判定と表示・エクスポート | 完了 | f7ce21c | 1 / 0 | 33 | 指摘 0 件（0 / 0） | なし | - |
| T07 | test-server の確認ページ、HTTPS 専用ヘッダーの「対象外」 | 完了 | 062d971 | 1 / 0 | 29 | 指摘 0 件（0 / 0） | なし | - |
| T08 | 版上げ 1.8.1 と文書 | 完了 | 6cfd5f1 | 1 / 0 | 14 | レビュー省略 | なし | - |

- 設計で書いたテストが実装の前から通っていたタスク（夜間ログの red-check。無ければ「なし」）: なし
- テストレビューで、指摘 0 件だったタスクの「検討した観点」（consideredPoints）の要点: 各タスクの受け入れ条件（仕様の解釈、境界値、陽性・陰性）、未観測時の unknown 優先（SPEC-01）、既存機能および旧 DB との後方互換性、要確認件数とバッジの正確性、表示・エクスポートの整合性、一次資料に基づく根拠 URL と確認日、H4 の遵守（推定結果を「該当なし」「安全」と断定しないこと）

## 4. テスト結果

| コマンド | 結果 | 件数・要点 |
| --- | --- | --- |
| `npm test`（vitest） | 合格 | passed 1684 / skipped 0 / failed 0 |
| `npm run reports:lint` | 合格 | 回帰用フィクスチャで全項目合格（0s） |
| `npm run build` | 合格 | content-script 12.03 KB、service-worker 236.61 KB、dist 合計 1103.28 KB |
| 同梱 DB | 合格 | schema 2.3, dataVersion 20261108, 収録件数 417 件（fixed: 300, none: 12, partial: 9, unknown: 96）, 合計サイズ 973.09 KB, distro 節 244.79 KB（上限 800 KB 以内）, releases 22 件, mapEntries 74 件, advisoryReleases 10 件 |
| 外部データの取得（`[T02][data]`・`[T05][data]`） | 取得済み | `[T02][data]` コミット（994b977: endoflife.date ライフサイクル 22 件）、`[T05][data]` コミット（0e49217: OSV Debian 479 件 / Ubuntu 393 件）により取得完了。distro 節の出典とライセンス（_source）: OSV.dev Debian (license: null, licenseNote: "v1.8.2 で確認", 479 レコード), OSV.dev Ubuntu (license: "CC-BY-SA-4.0", 393 レコード), endoflife.date (license: "MIT", 22 レコード) |
| DB だけのリリースの予行（`scripts/ci/rehearse-db-release.mjs`） | 合格 | passed 1684 / skipped 0 / failed 0（5s）、distroDigest を含む整合性再計算が正常に通過 |
| `npm run test:e2e` | 未実行（夜間モード。人間が確認） | 人間による目視および E2E 実行待ち |
| `node scripts/dev/check-v1.8.1.mjs` | PASS（25 件 PASS / 0 件 WARN / 1 件 FAIL） | 失敗は完了報告書未作成だった C14（本報告書の作成で解消）、WARN なし |

- v1.8.0 ベースライン: passed 1083 前後 / skipped 0 / failed 0
- skip 中のテスト（REPORT_DATA.json の vitest.skipped をそのまま転記。0 件なら「なし」）: なし
- 期待値を変えた既存テスト（全件。設計メモの「期待値を変えた既存テスト」から。なければ「なし」）:
  - `tests/advisory-pipeline.test.mjs`: 「生成結果は strict 検証 (schema 2.2) に合格する」の期待 `schemaVersion` を `'2.2'` → `'2.3'` に更新（H7）。「T16 (D4): schemaVersion 変更…」の変更後合成スキーマを `'2.3'` → `'9.9'` に更新（生成 DB 自体が 2.3 になったため）。
  - `tests/advisory-db-invariants.test.ts`: 「DB メタデータ…」の許容スキーマに `'2.3'` を追加（H7）。
  - `tests/fixtures/advisory-db.fixture.json`: schema を 2.3 に更新、`distro` 節と `integrity.distroDigest` を追加、`integrity.digest` を libraries の実測 sha256 値に修正（固定 DB の照合結果は不変）。
  - （※ `tests/review-v1.6.5-acceptance.test.ts` を含む他の既存テストの期待値は一切変更なし）

## 5. 変更の概要（利用者から見た変化）

1. **OS リリースの推定とライフサイクルに基づく EOL 判定 (T02, T03):**
   - HTTP レスポンスヘッダー（`Server`, `X-Powered-By`）に含まれる OS の印（Debian, Ubuntu, RHEL, CentOS, AlmaLinux, Rocky Linux）やパッケージ版の印（`ubuntuN`, `+debNuM`, `~debNuM`, `.elN`）、およびディストリ対応表（`distro-map.json`）の突き合わせにより、稼働している OS リリース（例: `Ubuntu 20.04 LTS`, `Debian 12 (bookworm)`）を推定・表示。
   - 推定した OS の標準サポート期限（endoflife.date 由来）に基づき、サポート終了翌日から EOL 診断（`SEC-EOL-*`）を実施。サポート期間中の場合は断定せず「Unknown（推定）」として扱い、「安全」「該当なし」などの過剰な断定を防止（H4）。
   - 第三者リポジトリ（`deb.sury.org`, `+ubuntuNN.NN`）やバックポート（`~bpoN`）を検出し、誤推定を防ぐための注記を表示。
2. **ディストリの脆弱性情報照合 (T05, T06):**
   - OSV.dev から取り込んだ Debian / Ubuntu の公式セキュリティ情報（DSA, USN 等）と照合し、上流で脆弱性が報告されている CVE についてディストリ側での修正状況を 6 区分（`fixed`, `not-fixed`, `open`, `unknown-revision`, `no-data`, `not-affected`）で判定。
   - パッケージ版が修正版未満の CVE がある場合は `not-fixed`、未修正の場合は `open` として明示。Ubuntu Pro（ESM）でのみ提供されている修正には ESM の印を表示。
   - 修正が確認できない CVE が存在する技術には、新しい警告指摘 `SEC-DISTRO-CVE-<技術>`（severity: LOW）を 1 件生成し、要確認件数およびバッジに反映。
3. **HTTPS 専用セキュリティヘッダーの「対象外」判定 (T07):**
   - HTTP（non-secure context）のページにおいて、ブラウザによって無視される COOP（`Cross-Origin-Opener-Policy`）および COEP（`Cross-Origin-Embedder-Policy`）ヘッダーを、従来の INFO や誤警告ではなく「対象外（N/A）」として診断・表示。
   - 要確認件数やバッジには含めず、余分な警告を抑制（H6）。
4. **test-server の検証ページ拡充 (T07):**
   - WAF 確認画面（Cloudflare, AWS WAF）、外部 CDN SRI、各ディストリのバナー（Ubuntu, Debian, RHEL, sury, バックポート, 未対応版）、HTTPS 専用ヘッダーなどのテストページを追加。

## 6. 指示からの逸脱・判断事項

| 箇所 | 指示 | 実際に行ったこと | 理由 |
| --- | --- | --- | --- |
| T01 (dpkg 比較) | dpkg 自身のテスト（`lib/dpkg/t/t-version.c`）の比較例を取り込み、すべて成り立つ | 空の版どうしの比較および数字以外で始まる upstream の比較は、文字列として等価な形（`0:0 < 2:0`、`0a-0 < 0b-0`）に書き直してテストに収録。upstream のコロン（`0:0:0-0`）は Policy の文字一覧には無いが dpkg 実装に合わせて許容 | t-version.c は文字列ではなく構造体の組で比較しているため。また、数字始まり規則（A3）や dpkg の挙動との整合性を保つため |
| T02 (対応表) | RHEL 系の対応表を組み込む | RHEL 本体の一覧はログインが必要なため、ソースが同一の再ビルド（Rocky Linux, AlmaLinux, CentOS Vault）の公開リポジトリで確認できた製品・版のみを収録。確認できなかったものは未収録とした | 確証のない推測による誤判定を避ける安全側の設計（確信度 none として扱い誤った EOL 判定を防ぐ） |
| T04 (週次突き合わせ) | sources.debian.org API で Debian の版を確認 | sources.debian.org API では `-security` suite の版が即座に取得できない場合があることを確認したが、指示書の指定どおり sources.debian.org を採用し、例外発生時もスクリプトは exit 0 で終了するように実装 | 外部 API の一時的な不調や制限によって週次 CI パイプラインを失敗させないため |
| T05 / T06 (not-affected の扱い) | §4.2 で `not-affected` 区分を定義 | OSV の Debian / Ubuntu データには「影響なし」を表すレコードが存在しないため、DB パイプラインでは `not-affected` レコードを生成せず、データに無い CVE は `no-data`（要確認）として判定 | レコードが無いことをもって「安全」「影響なし」と誤認・断定することを防ぐため（H4・H4a） |
| T06 (要確認件数) | §4.2「数える（第1段階と同じ）」 | 数える区分の CVE がある技術ごとに `SEC-DISTRO-CVE-<技術>` 指摘を 1 件生成。CVE ごとに指摘を作らない | CVE ごとに指摘を生成すると要確認件数が急増し、「警告を増やしすぎない」設計原則に反するため |
| T07 (対象外 status) | HTTPS 専用ヘッダーを「対象外」とする | `SecurityStatus` に `'not-applicable'` を新設し、要確認件数・重大度別集計から除外して `securityFindings.notApplicable` に計上 | 既存の pass/info/warning/fail/unknown のいずれとも異なる新しい概念であり、既存の集計ロジックやバッジ表示を崩さないため |
| 全体（main の取り込み） | §9 起点は 0e891fa | 作業の最後に main の 1.8.0.1（DB のみの更新）を取り込み、advisory-db.json と build-report.json を build-db で作り直した。総合チェック C13 は、起点に無い CVE（apache の 1 件）を「基準外の DB の変更」として指摘する | 1.8.0.1 で DB が更新されたため。C13 は起点からの DB の差分を見る仕組みなので、取り込みによる増加は想定どおりで、手で DB を編集したものではない |
| T04（週次の突き合わせ） | 対応表の項目を Launchpad / sources.debian.org と突き合わせる | 両 API では引けない family（RHEL 系）を「対象外」として件数と内訳に残し、PR の本文にも出すようにした（ドリフト判定には加えない） | 黙って除外すると全件を確認したように見え、人が確かめるべき項目が見落とされるため |

## 7. 未解決の問題・既知の制限