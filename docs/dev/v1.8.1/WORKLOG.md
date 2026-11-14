# v1.8.1 作業記録

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

## T01 設計  (2026-11-14 03:32)
- 変更ファイル: docs/dev/v1.8.1/design/T01.md（新規）, tests/dpkg-version.test.ts（新規）
- 判断したこと:
  - 新しいモジュール `src/security/dpkg-version.ts` の公開 API を `parseDpkgVersion(s: string | null | undefined): { epoch, upstream, revision } | null` と `compareDpkgVersions(a, b): -1 | 0 | 1 | null` に決めた。revision が無いときは `''`、epoch が無いときは 0。
  - dpkg のテスト（t-version.c）は版を「組」で比べるので、同じ意味の文字列に書き直して取り込んだ。空の版どうしの比較は文字列にできないので取り込まず、upstream が `a`・`b` の比較は「数字以外で始まる upstream は null」と両立させるため先頭に `0` を付けた（設計メモ「仕様の解釈」1）。
  - upstream のコロンは、Policy の文字の一覧には無いが dpkg の実装とテストが受け付けるので、dpkg に合わせて許す（受け入れ条件「t-version.c の例がすべて成り立つ」のため）。
  - 前後のスペース・タブは dpkg と同じく無視し、途中の空白は null。epoch は数字だけ・上限 2147483647（dpkg の `strtol` が受ける `+1:` などは安全側で null）。
  - 数字の部分は数に変換せず 1 文字ずつ比べる（桁の多い数のテストを置いた）。
  - 「isLinuxPackageVersion と version-matcher の挙動は変えない」は、実装前に実測した戻り値を固定するテストで確かめる。
  - 実装の前は、モジュールが無いためファイル全体が失敗することを確認した。設計の担当が規則どおりの参照の実装（コミットしない）で全件が通ることも確かめた。次の版を前提にした test-hygiene の検査でも違反は無い。
- 外部の事実:
  - 版の形式・使える文字・比較の手順（`~` は空より前、英字は記号より前、revision 無しは 0）— https://www.debian.org/doc/debian-policy/ch-controlfields.html#version （Debian Policy 4.7.4.1、2026-11-14）
  - dpkg のテストの比較例・解析の例 — https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/t/t-version.c （2026-11-14。git.dpkg.org は自動取得を拒否したため Salsa で確認）
  - dpkg の比較と解析の実装（`order`・`verrevcmp`・`parseversion`）— https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/version.c 、https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/parsehelp.c （2026-11-14）
- 未解決: なし

## T01 実装  (2026-11-14 03:38)
- 変更ファイル: src/security/dpkg-version.ts（新規）
- 判断したこと:
  - 設計メモ（T01.md）の「実装の方針」に従い、`src/security/dpkg-version.ts` を新規作成して `parseDpkgVersion` と `compareDpkgVersions` を実装した。
  - `parseDpkgVersion` では、前後の空白（スペース・タブ）を除去し、途中の空白や空文字列は null を返却。epoch は 1 文字以上の数字かつ `INT_MAX`（2147483647）以下のみ許容し、upstream は数字始まりかつ `[0-9A-Za-z.+~:-]`（コロン許容）、revision は省略時空文字 `''`、存在時は `[0-9A-Za-z.+~]` の文字種検査を行い、不正な入力には例外を投げず null を返すようにした。
  - `compareDpkgVersions` では、Debian Policy 5.6.12 および dpkg の `order()` / `verrevcmp()` アルゴリズムに準拠し、非数字部分と数字部分（先頭ゼロ無視、桁数および数値差判定）の交互比較を実装。結果を `-1 | 0 | 1 | null` に正規化して返却するようにした。revision 省略（空文字）と `0` の比較も自然に等価として判定される。
  - `src/security/version-matcher.ts` など既存モジュールは一切変更せず、既存の挙動を維持した。
- 未解決: なし

## T02 設計  (2026-11-14 11:45)
- 変更ファイル: docs/dev/v1.8.1/design/T02.md（新規）, tests/distro-map.test.ts（新規）, tests/advisory-distro-pipeline.test.mjs（新規）, tests/advisory-distro-compat.test.ts（新規）, tests/advisory-db-invariants.test.ts, tests/advisory-pipeline.test.mjs, tests/fixtures/advisory-db.fixture.json
- 判断したこと:
  - `distro.releases` の「標準サポート終了」は endoflife.date の `eol`、「延長サポート終了」は `extendedSupport`（`false`・無しは null）。`lts` は真偽値または日付の文字列を真とする。
  - 収録リリースは H8 に加え、サポート中の Ubuntu 26.04 LTS と、2026-11-14 時点でサポート中の唯一の中間リリース 26.10。RHEL 系は 7〜10 のうち endoflife.date にあるもの（CentOS 7・8、AlmaLinux と Rocky の 8〜10）。
  - RHEL 本体の一覧はログインが要るため、ソースが同じ再ビルド（Rocky・AlmaLinux・CentOS の公開リポジトリ）で確かめた。確かめられなかった製品（RHEL 7 系の openssl・php、RHEL 8 系の php など）は載せない（T03 で確信度 none になり、誤った推定より安全）。
  - evidenceUrl はディストリ自身の公開サイトのホストだけを許す（一覧は設計メモ）。対応表の不正（curated の誤り）は build-db を失敗させ、OS のライフサイクルの取得結果が無いことは警告だけにする。
  - integrity は既存の `digest`（libraries）を変えず、`distroDigest` を足す。distro 節があるのに distroDigest が無い・一致しない DB は validateDb が拒否する。
  - `--distro-only` は manifest の `fetchedAt`（build-db の基準日）を進めない。通常の週次の取得でも OS を取る。
  - 固定 DB を schema 2.3 にし、distro 節（抜粋）と distroDigest を足した。あわせて、以前から libraries と一致していなかった `integrity.digest` を実際の値に直した（libraries は変えていない。固定 DB を使う既存テスト 9 ファイル・258 件が通ることを確認）。
  - 既存テストの期待値の変更: advisory-pipeline の schema（2.2→2.3）と、schema 変更の合成値（2.3→9.9）、advisory-db-invariants の許す schema に 2.3 を追加（理由は設計メモ）。
  - 実装の前に新しいテストが「機能が無い」ために失敗すること、参照の実装（コミットしない）では本物のファイルに依存しないケースがすべて通ること、対応表の候補で tests/distro-map.test.ts が全件通ること、提案した型で型検査が通ること、test-hygiene が通ることを確かめた。
- 外部の事実:
  - endoflife.date の応答の項目（cycle・codename・releaseDate・eol・support・extendedSupport・lts・latest）と OS の slug、各サイクルの有無 — https://endoflife.date/api/ubuntu.json ほか（debian・rhel・centos・almalinux・rocky-linux）（2026-11-14）
  - Ubuntu のシリーズ（26.10 stonking がサポート中の唯一の中間リリース、26.04 resolute） — https://api.launchpad.net/1.0/ubuntu/series （2026-11-14）
  - nginx 1.18.0 が Ubuntu 20.04（1.18.0-0ubuntu1.x）と 22.04（1.18.0-6ubuntu14.x）の両方にある — Launchpad の getPublishedSources（focal・jammy）（2026-11-14）
  - Debian 10 の apache2・nginx・openssl の版 — https://sources.debian.org/api/src/apache2/ ほか（2026-11-14）
  - Rocky Linux 9 の php の版（8.0.30、モジュールの 8.1・8.2・8.3） — https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/p/ （2026-11-14）
  - 対応表の各行の根拠は設計メモの「外部の事実」の表と、各項目の evidenceUrl。
- 未解決:
  - RHEL 系の対応表は、確かめられた製品だけ（RHEL 7・CentOS 7 の openssl・php、RHEL 8 系の php、AlmaLinux 8・9 の一部は未収録）。人が一次資料で確かめて足すかを判断する。
  - Debian の changelog から拾った版（bullseye の apache2 2.4.49・2.4.50 など）は、tracker.debian.org の changelog に依った。T04 の週次の突き合わせで、ずれがあれば報告される。

## T02 実装  (2026-11-14 12:03)
- 変更ファイル: src/shared/types.ts, data/advisories/catalog.json, data/advisories/distro-map.json（新規）, scripts/advisories/lib/util.mjs, scripts/advisories/lib/eol.mjs, scripts/advisories/lib/distro.mjs（新規）, scripts/advisories/build-db.mjs, scripts/advisories/fetch-upstream.mjs, scripts/validate-advisories.mjs, scripts/ci/rehearse-db-release.mjs
- 判断したこと:
  - 設計メモ（T02.md）および INSTRUCTIONS.md の指示に厳密に従い、OS ライフサイクル表および上流版→OS リリース対応表（distro-map.json）の DB パイプラインへの組み込みを実装した。
  - `src/shared/types.ts`: `DistroFamily`, `DistroProduct`, `DistroMapEntry`, `DistroMapFile`, `DistroReleaseLifecycle`, `AdvisoryDistroSection` を定義。
  - `data/advisories/catalog.json`: トップレベルに `distros`（ubuntu, debian, rhel, centos, almalinux, rocky）を追加。
  - `data/advisories/distro-map.json`: 設計メモの「外部の事実」に記載された curated データをそのまま転記して新規作成。
  - `scripts/advisories/lib/util.mjs`: `PATHS.distroMap` を追加。
  - `scripts/advisories/lib/eol.mjs`: OS ライフサイクル取得用の圧縮関数 `compactDistroEolCycles` を追加。
  - `scripts/advisories/lib/distro.mjs`: 新規作成し、`DISTRO_FAMILIES`, `DISTRO_PRODUCTS`, `DISTRO_EVIDENCE_HOSTS`, `isDistroEvidenceUrl`, `validateDistroMapEntry`, `buildDistroSection`, `validateDistroSection` を実装。
  - `scripts/advisories/build-db.mjs`: `OUTPUT_SCHEMA_VERSION = '2.3'` に更新。`buildDatabase` に `distroMap` 引数を追加し、`catalog.distros` または `distroMap` が存在するときに `distro` 節と `integrity.distroDigest` を出力するよう更新。`loadUpstream` で `distro-eol` ディレクトリを読み込む際に `upstream.distroEol` に正しく格納されるよう `read` 関数のプロパティ名指定を修正。また macOS 等のシンボリックリンク環境下で CLI 実行判定が正しく機能するよう `fs.realpathSync` を用いた判定に更新。
  - `scripts/advisories/fetch-upstream.mjs`: `parseArgs` を export し `--distro-only` オプションを実装。`distroOnly: true` の時は OS ライフサイクルのみを取得し、製品・KEV・PSL を取得せず、manifest の `fetchedAt` を維持するようにした。また、通常の週次取得（`!args.distroOnly` かつ `!args.only`）時にも OS ライフサイクルを取得するようにした。同様に CLI 実行判定を `fs.realpathSync` を用いた判定に更新。
  - `scripts/validate-advisories.mjs`: `SUPPORTED_SCHEMA_VERSIONS` に `'2.3'` を追加。2.2/2.3 共通の検査（origin, fixStatus, eolDate）を適用。`db.distro` が存在する場合は `validateDistroSection` で検証し、`db.integrity` がある場合は `distroDigest` の一致を検証。
  - `scripts/ci/rehearse-db-release.mjs`: `bumpAdvisoryDb` で `db.distro` が存在する場合に `integrity.distroDigest` を再計算するよう更新。
- 未解決: なし

## T03 設計  (2026-11-15 06:40)
- 変更ファイル: docs/dev/v1.8.1/design/T03.md（新規）, tests/distro-inference.test.ts（新規）, tests/distro-inference-report.test.ts（新規）
- 判断したこと:
  - 新しいモジュール `src/detection/distro-inference.ts` の公開 API を `inferDistroFromHeaders(headers, distro)`（製品ごとの `distroInference`）と `judgeDistroEol(inference, distro, now)`（`{ basisRelease, eolInfo }` か null）にした。型 `DistroInference` などは `src/shared/types.ts`、`DetectedTechnology` に任意の `distroInference`・`upstreamEolInfo` を足す。
  - 印の一覧をテストで固定した: 括弧内の OS 名 6 種、`ubuntuN`・`[+~]debNuM`・`.elN`（`.elN_M` を含む）、第三者 `deb.sury.org`・`+ubuntuNN.NN`、バックポート `~bpoN`。PPA 一般と Ubuntu の `~NN.NN` は一次資料で規則を確かめていないので印にしない（安全側）。
  - H4 により、推定で標準サポート中のときは `Supported` にせず `Unknown`（終了予定日と「推定」を文言に書く）。終了日の翌日から EOL。重大度・status は既存の `SEC-EOL`（SPEC-04）と同じ。
  - 二重に数えないこと: 製品ごとに EOL の指摘は最大 1 件。上流の EOL は `upstreamEolInfo`（参考）にして、件数・指摘に使わない。
  - 候補のどれかにライフサイクルが無い（`distro.releases` が空など）ときは EOL を判定せず第1段階のまま。照合 DB を差し替えたとき、差し替えた DB に `distro` が無ければ同梱 DB で補わない（`distro` 節が無い DB では第1段階と同じ出力）。
  - OpenSSL は技術一覧に足さないが、Server ヘッダーの `OpenSSL/<版>` を積集合の手がかりにする（§3.1 手順 3.3 の例）。
  - `~bpo` の版は第1段階で `distroHint` が付かず上流の版で照合される。§3.2「第三者は第1段階の表示のまま」に従い照合の区分は変えず、Needs Review の検査の対象から外した（`thirdParty` と注記は検査する）。
  - 実装の前に、単体テストはモジュールが無いため読み込みで失敗し、統合テストは 43 件中 38 件が「推定が付かない・EOL を OS で判定しない・表示が無い」ために失敗することを確かめた（通る 5 件は陰性・前提・旧 DB の互換）。作業用の参照実装（コミットしない）で単体テスト 57 件がすべて通ること、設計メモの型で新しいテストの型検査が通ること、test-hygiene が通ることを確かめた。
  - 既存テストの期待値は変えていない。固定 DB の `distro` 節により実装の後は既存テストの Ubuntu などの製品にも推定が付くが、既存テストが見る項目（`distroHint`・照合の区分・`Apache/2.4.58 (Ubuntu)` の `Unknown`）は変わらないことを読んで確かめた。
- 外部の事実:
  - Debian の安定版の更新の版は `+debXuY`／`~debXuY` — https://www.debian.org/doc/manuals/developers-reference/pkgs.en.html （5.5.1、2026-11-15）
  - Debian のバックポートの版は `~bpo${release}+${build}` — https://backports.debian.org/Contribute/ （2026-11-15）
  - deb.sury.org の版は `+ubuntuNN.NN.N+deb.sury.org+N` — https://launchpad.net/~ondrej/+archive/ubuntu/php （2026-11-15）
  - RPM の Release の dist タグ（例 `34.el7`） — https://rpm-packaging-guide.github.io/ （2026-11-15）。RHEL 9 系の `.el9`・`.el9_N` — https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/h/ （2026-11-15）
  - Fedora の DistTag の文書はボット対策の画面で読めなかった（採用しない）。
- 未解決:
  - 同じ OS の上の複数の製品（Apache と PHP など）が OS の EOL になったとき、指摘は製品ごとに 1 件ずつ出る（既存の SPEC-04 と同じ数え方）。OS 単位に 1 件にまとめるかは人が判断する。
  - Ubuntu の `~NN.NN`（SRU の版）をリリースの印にするかは、一次資料で規則を確かめてから判断する（現在は対応表で引く）。

## T03 実装  (2026-11-15 07:05)
- 変更ファイル: src/shared/types.ts, src/detection/distro-inference.ts（新規）, src/detection/advisory.ts, src/detection/engine.ts, src/background/service-worker.ts, src/popup/render.ts, src/dashboard/render.ts, src/export/markdown.ts, src/export/csv.ts, docs/DETECTION_SPECIFICATION.md
- 判断したこと:
  - 設計メモ（T03.md）および INSTRUCTIONS.md の仕様に従い、Server・X-Powered-By ヘッダーからの OS リリース推定とライフサイクルによる EOL 判定を実装した。
  - `src/shared/types.ts`: `DistroInferenceConfidence`, `DistroInferenceEvidence`, `DistroThirdPartyInfo`, `DistroInference` を追加。`DetectedTechnology` に `distroInference` と `upstreamEolInfo` を追加。
  - `src/detection/distro-inference.ts`: 新規作成し、`inferDistroFromHeaders` および `judgeDistroEol` を実装。
    - 括弧内の OS 名（6種）とパッケージ版の印（`ubuntuN`, `+debNuM`, `~debNuM`, `.elN`, `.elN_M`）の解析。
    - 第三者リポジトリ（`deb.sury.org`, `+ubuntuNN.NN`）およびバックポート（`~bpoN`）の検出時は `thirdParty` を付与し推定を行わない。
    - パッケージ版の印によるリリース特定（確信度 high）、対応表突合（1件: medium, 2件以上: low, 0件: none）と、複数製品の積集合（1件なら high、空なら各候補保持）。OpenSSL トークンも積集合の手がかりとして活用。
    - `judgeDistroEol` では、標準サポート終了日の翌日に EOL と判定し、当日・前日は EOL にせず Supported とも断定しない（Unknown）。2件以上の場合は最も早く終わる候補で判定し候補を併記。
    - C18 対策として、ファイル内および生成文言から「該当なし」「安全」「Not Affected」を徹底して排除した。
  - `src/detection/advisory.ts`: `AdvisoryDatabase` に `distro` 節を追加。差し替え DB 存在時は同梱 DB で補わない `getActiveDistroSection()` と、上流 EOL 照合用の `matchUpstreamEol()` を追加。
  - `src/detection/engine.ts`: `detect()` の末尾で `getActiveDistroSection()` が存在する場合に `inferDistroFromHeaders` を実行し、製品に `distroInference` を付与。ライフサイクルで判定可能な場合は EOL 情報およびインスタンス EOL を更新し、上流 EOL を `upstreamEolInfo` に参考として記録。
  - `src/background/service-worker.ts`: EOL 指摘（`SEC-EOL-*`）の生成時に OS リリース推定に基づく判定である場合は観測値・説明に推定である旨を明記。上流 EOL は数えず二重カウントを防止。
  - `src/popup/render.ts` & `src/dashboard/render.ts`: ポップアップモーダルおよびダッシュボード詳細に「OS リリースの推定」セクションを追加し、リリース・確信度・エスケープ済み根拠ヘッダー値・注記・参考上流 EOL を表示。ライブラリセキュリティ表の EOL 列にも反映。レビュー指摘に基づき、リリース表示名変換において CentOS / AlmaLinux / Rocky Linux の置換も対応。
  - `src/export/markdown.ts`: 第4節に「OS リリースの推定」小節を出力。推定対象がある場合のみサブセクションを追加し `reports:lint` と回帰テストの双方に適合。リリース表示名変換に CentOS / AlmaLinux / Rocky Linux の置換を追加。
  - `src/export/csv.ts`: 技術一覧に「OSの推定」列を追加し、リリース・確信度・第三者注記を出力。レビュー指摘に基づき候補およびリリース表示で CentOS / AlmaLinux / Rocky Linux の置換を追加。
  - `docs/DETECTION_SPECIFICATION.md`: レビュー指摘に基づき、§6.4 に印の一覧表（括弧内 OS 名 6 種、対象外 OS 名 4 種、パッケージ版印 3 種、対象外印 `.fcNN`、第三者・バックポート印）、推定およびライフサイクル EOL 判定の手順の要点（手順 2.1・2.2）、Markdown 表形式の区切り線（`| --- | --- |`）を持つ確信度の表を追記。
- 外部の事実:
  - 設計メモ（T03.md）の「外部の事実」に記載された一次資料に基づく値（Debian の `+debXuY`/`~debXuY`・`~bpo`、deb.sury.org の書式、RHEL の `.el9`、endoflife.date のライフサイクル・slug など）のみを使用した。
- 未解決: なし

## T04 設計  (2026-11-15 07:15)
- 変更ファイル: docs/dev/v1.8.1/design/T04.md（新規）, tests/distro-map-drift.test.mjs（新規）, tests/advisory-db-update-workflow.test.ts（新規）
- 判断したこと:
  - 新しい `scripts/advisories/check-distro-map.mjs` の公開 API を `checkDistroMap({ distroMap, fetchJson, now })`（突き合わせだけ）と `runDistroMapCheck({ mapPath, reportPath, fetchJson, now })`（対応表を読み、build-report.json の `distroMapDrift` だけを書く。例外を投げない）にした。結果の区分は `drift`（ずれ）・`none`（なし）・`unchecked`（未確認）。
  - 「現在の版」は、Ubuntu が Launchpad の `Published` で `Release`・`Updates`・`Security` のポケット（Proposed・Backports は数えない）、Debian が sources.debian.org でそのリリースのコード名の suite（`-updates`・`-security` も可。`-proposed-updates`・`-backports` は数えない）。T02 で対応表を作ったときの基準に合わせた。
  - 上流版は epoch と revision を外した先頭の数字の部分で比べる。不正な文字を含む版は捨てる（PR の本文に外部の文字列をそのまま入れない）。
  - 全体の結果は、ずれが 1 件でもあれば「ずれ」、ずれが無く未確認があれば「未確認」（一部しか確かめていないのに「なし」と断定しない）、すべて一致したときだけ「なし」。
  - RHEL 系は §5.4 の API の対象外なので、問い合わせず結果にも入れない（毎週「未確認」が出て警告が増えすぎるのを避ける）。
  - pr-plan は `distroMapDrift` があれば状態にかかわらず「対応表のずれ」の節を作り、PR の作成・ラベル・自動マージ・ジョブの成否は変えない（ずれがあっても PR を止めない）。CLI は `--build-report <path>` で読む。
  - ワークフローは「Validate advisory DB」の後にステップを足す（build-db が build-report.json を作り直した後、pr-plan の前）。`continue-on-error` と `|| true` は使わず、スクリプトが必ず 0 で終わる。
  - CLI のテストは、一時ディレクトリにスクリプトと対応表をコピーし、実パスに解決してから `node --import <preload>` で `globalThis.fetch` を「HTTP 404 を返す偽物」に差し替えて実行する（ネットワークに出ない）。
  - 実装の前に、check-distro-map のテストはモジュールが無いため読み込みで失敗し、ワークフローのテストは 10 件中 4 件が「ステップが無い・`--build-report` が無い」ために失敗することを確かめた。作業用の参照実装（コミットしない）で 2 ファイル 55 件がすべて通ること（CLI と actionlint の実行を含む）、test-hygiene と型検査が通ることを確かめた。
  - 既存テストの期待値は変えていない。
- 外部の事実:
  - Launchpad の `getPublishedSources` の応答（`start`・`total_size`・`entries[]`・`next_collection_link`、各要素の `source_package_name`・`source_package_version`・`status`・`pocket`） — https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=nginx&exact_match=true&distro_series=https://api.launchpad.net/1.0/ubuntu/jammy&status=Published （2026-11-15）
  - `getPublishedSources` の引数と `pocket` の値 — https://api.launchpad.net/devel.html#archive （2026-11-15。文書が大きく該当箇所は要約で確認。実際の応答の値で裏付けた）
  - sources.debian.org の `/api/src/<pkg>/` の応答（`versions[]` の `suites`・`version`）と、無いパッケージが HTTP 200 の `{"error":404}` になること — https://sources.debian.org/api/src/apache2/ 、https://sources.debian.org/doc/api/ （2026-11-15）
- 未解決:
  - sources.debian.org の応答には `-security` の suite が出なかった（確かめた 3 パッケージ）。Debian のセキュリティ更新だけで出た上流版は、次のポイントリリースまでこの突き合わせでは見えないことがある。指示書（§5.4）が sources.debian.org を指定しているので従った。より細かく見るなら、人が別の一次資料（security-tracker.debian.org など）を使うかを判断する。
  - PR を作らない週（DB の差分が none）は、突き合わせの結果が PR の本文に載らない（ワークフローの成果物の build-report.json には残る）。毎週通知が要るかは人が判断する。


