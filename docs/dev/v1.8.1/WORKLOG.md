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



## T04 実装  (2026-11-15 07:25)
- 変更ファイル: scripts/advisories/check-distro-map.mjs（新規）, scripts/advisories/pr-plan.mjs, .github/workflows/advisory-db-update.yml
- 判断したこと:
  - 設計メモ（T04.md）および INSTRUCTIONS.md の仕様に厳密に従い、対応表（distro-map.json）の週次突き合わせ処理を実装した。
  - `scripts/advisories/check-distro-map.mjs`: 新規作成。
    - `extractUpstreamVersion`: dpkg 形式の版から epoch と revision を除去し、先頭の上流版パターン（`/^\d+(?:\.\d+)+[a-z]?/`）を取り出す。不正文字や 100 文字超の版は除外。
    - `checkDistroMap`: Ubuntu は Launchpad の `getPublishedSources` を用い、`Published` かつ `Release`・`Updates`・`Security` ポケットの公開版を取得（`next_collection_link` による最大 20 ページのページ送りに対応）。Debian は `sources.debian.org/api/src/<pkg>/` を用い、該当リリースの suite（`<codename>`, `<codename>-updates`, `<codename>-security`）の版を取得（同一パッケージの取得結果をキャッシュ）。双方で対応表に無い上流版を検出し、`drift` / `none` / `unchecked` を判定。RHEL 系は対象外としてスキップ。
    - `runDistroMapCheck`: 対応表ファイルを読み込み、`build-report.json` の `distroMapDrift` を更新。対応表ファイル自体の内容は一切変更せず、例外発生時も `unchecked` を記録して終了。
    - CLI 実行時は `createFetchJson`（retries: 2）を使用し、例外発生時を含め必ず `process.exit(0)` で終了。
  - `scripts/advisories/pr-plan.mjs`:
    - `renderDistroMapDriftSection`: `distroMapDrift` から Markdown 節を生成。全体が `none` のときのみ「なし」を用い、件数は「一致 N 件」と表記して未確認時に「なし」が含まれないよう配慮。Markdown 挿入前に値をサニタイズ。
    - `planPullRequest`: 任意の `distroMapDrift` 引数を受け取り、`classification !== 'none'` の場合に本文末尾へセクションを追加。PR 作成・ラベル・自動マージ等の判定には影響を与えない。
    - CLI: `--build-report` 引数を追加し、`distroMapDrift` が存在する場合に `planPullRequest` へ渡す。
  - `.github/workflows/advisory-db-update.yml`:
    - `Validate advisory DB` の直後に `Check distro map drift` ステップ（`node scripts/advisories/check-distro-map.mjs`）を追加。`continue-on-error` や `|| true` は不使用。
    - `Plan pull request` のステップ引数に `--build-report data/advisories/build-report.json` を追加。
- 外部の事実:
  - 設計メモ（T04.md）の「外部の事実」に記載された一次資料に基づく値（Launchpad API の `getPublishedSources`、sources.debian.org API の形式等）のみを使用した。
- 未解決: なし

## T05 設計  (2026-11-16 00:41)
- 変更ファイル: docs/dev/v1.8.1/design/T05.md（新規）, tests/osv-distro-pipeline.test.mjs（新規）, tests/ci-check-size-distro.test.ts（新規）, tests/advisory-db-invariants.test.ts（T05 の describe を追記）, tests/advisory-distro-pipeline.test.mjs（合成の catalog に `distroSources` を追加。期待値は変えていない）
- 判断したこと:
  - `distro.advisories` の形を「リリース → ソースパッケージ → CVE の配列」、各 CVE を `{ cve, status, fixedVersions, esm?, osvIds }` にした（§5.3 の「CVE ID・修正版・区分・ESM の印・OSV ID」）。区分は `fixed`・`open`（・形だけ受け付ける `not-affected`）。
  - OSV の Debian / Ubuntu データには「影響なし」を表す項目が無い（Ubuntu は not-affected と DNE を載せない、Debian の変換器は影響なしのリリースを飛ばす）。載っていないことから not-affected を作ると H4a で要確認件数から消えるので、作らない。その CVE はそのリリースに記録せず、T06 では no-data（数える）になる。
  - 同じ CVE に CVE 単位のレコード（UBUNTU-CVE / DEBIAN-CVE）があれば、区分と修正版はそれだけで決める（USN / DSA は複数の CVE をまとめて持ち、リリースごとの対応があいまいなため）。OSV ID は両方残す。
  - パイプラインからは T01 の dpkg 比較（TypeScript）を使えないので、修正版が複数あるときは比べずに全部 `fixedVersions` に残す。T06 で「すべての修正版以上なら fixed」とするのが安全側（T06 の設計で決める）。
  - ESM の印は、標準のエコシステムに修正が無く、Ubuntu Pro のエコシステムか `+esm` / `~esm` の版にだけ修正があるときだけ付ける。Ubuntu の LTS は標準と Pro の 2 つを問い合わせ、どちらかの取得結果が無い対象は出さない（片方だけで判定しない）。
  - `_source` の出典の値（名前・URL・ライセンス）は人が管理する値なので catalog.json の `distroSources` に置き、distro 節を作るときに無い・欠けている・license も licenseNote も無いなら build-db を失敗させる。`--check` は比べる前にコミット済みの DB の distro 節を検査し、原因（`_source` など）を出す。
  - サイズは `JSON.stringify(db.distro)` のバイト数（C17 と同じ）。check-size は DB が JSON として読めて distro 節があるときだけ `distro` の結果を足す（既存のテストの合成ファイルを壊さない）。build-db と validateDb も 800 KB を超えたら失敗する（§5.3）。
  - expectRed: 実装の前に tests/osv-distro-pipeline.test.mjs と tests/ci-check-size-distro.test.ts の 64 件中 58 件が、機能が無いため（`distro.advisories` が無い、`SIZE_LIMITS.distro` が無い、問い合わせが無いなど）失敗することを確かめた。通る 6 件は互換と陰性の確認。invariants の T05 の追記 2 件も、同梱 DB に `_source` が無いため失敗する（実装の後の build-db で通る）。test-hygiene・既存の T02 のテスト・型検査は通る。
  - 一時ディレクトリに参照実装を置いて通るかを確かめることは、夜間の権限でできなかった。設計メモの規則とテストの期待値を 1 件ずつ突き合わせて確認した。
- 外部の事実:
  - OSV のエコシステム名（`Debian:<番号>`、`Ubuntu:<YY.MM>:LTS`、`Ubuntu:Pro:<YY.MM>:LTS`、中間は `Ubuntu:<YY.MM>`）と範囲の書き方 — https://ossf.github.io/osv-schema/ 、https://documentation.ubuntu.com/security/docs/security-updates/osv/ （2026-11-16）
  - 実際のレコードの形（修正済み・未修正・ESM・upstream の CVE） — https://api.osv.dev/v1/vulns/UBUNTU-CVE-2024-38474 、https://api.osv.dev/v1/vulns/USN-6885-1 、https://api.osv.dev/v1/vulns/DEBIAN-CVE-2024-38474 、https://api.osv.dev/v1/vulns/DSA-5729-1 、https://api.osv.dev/v1/vulns/DEBIAN-CVE-2023-44487 、https://api.osv.dev/v1/vulns/UBUNTU-CVE-2023-44487 （2026-11-16）
  - 「影響なし」の扱い — Ubuntu の OSV の説明（上の URL の状態の対応表）、Debian の変換器 https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/converters/debian （2026-11-16）
  - 問い合わせの API — https://google.github.io/osv.dev/post-v1-query/ （2026-11-16）
  - ライセンス: Ubuntu は CC-BY-SA 4.0（https://github.com/canonical/ubuntu-security-notices 、https://google.github.io/osv.dev/data/ ）。Debian は表示を見つけられなかった（→ null と licenseNote）。endoflife.date はリポジトリの LICENSE が MIT（https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE ）（2026-11-16）
- 未解決:
  - 実データの distro 節が 800 KB に収まるかは、[T05][data] の取得まで分からない（Debian の CVE 単位のレコードは、そのリリースより前に直った古い CVE も含む）。超えたら build-db と check-size が失敗するので、人が対象（リリース・パッケージ）か圧縮の方法を決める。
  - Debian の OSV データのライセンスは一次資料で確認できなかった（`licenseNote` で v1.8.2 に持ち越し）。endoflife.date はデータ単独のライセンス表示が無く、リポジトリの MIT と指示書の指定に従った。
  - 指示書の §4.2 の `not-affected` は、OSV のデータからは作れない（上の判断）。T06 は固定 DB で区分を試せるが、実データでは出ない。人が「載っていない＝影響なし」とみなすかを判断する場合は、T06 以降で扱う。

## T05 実装  (2026-11-16 00:55)
- 変更ファイル: data/advisories/catalog.json, scripts/advisories/lib/osv-distro.mjs（新規）, scripts/advisories/lib/distro.mjs, scripts/advisories/build-db.mjs, scripts/advisories/fetch-upstream.mjs, scripts/ci/check-size.mjs, src/shared/types.ts
- 判断したこと:
  - 設計メモ（T05.md）およびタスク指示書（.agy-out/task-T05.md）の仕様に厳密に従い、OSV の Debian / Ubuntu データの取得・圧縮・DB 構築・検証を実装した。
  - `data/advisories/catalog.json`: `distroSources` に OSV.dev (Debian), OSV.dev (Ubuntu), endoflife.date の定義（URL・ライセンス情報を含む）を追加。
  - `scripts/advisories/lib/osv-distro.mjs`: 新規作成。
    - `isUbuntuLts`: 偶数年の .04 を LTS と判定。
    - `osvEcosystemsFor`: Debian は `Debian:<version>`、Ubuntu は LTS に `:LTS` および `Ubuntu:Pro:<version>:LTS`、非 LTS は `Ubuntu:<version>` を返す。
    - `osvDistroTargets`: 対応表から Debian / Ubuntu かつ apache, nginx, php の対象（重複なし）を抽出。
    - `compactOsvDistroVuln`: 1 レコードから当該パッケージ・エコシステムの行のみ抽出。CVE 単位レコードと通知単位レコードの CVE 抽出、ECOSYSTEM ranges からの introduced / fixed 抽出（説明文や versions 等は除去してサイズ最小化）。
    - `buildDistroAdvisories`: 対象エコシステムのスナップショットから `withdrawn` を除き、同一 ID を統合。CVE 単位レコード（cveLevel: true）を優先して区分（fixed / open）と修正版（重複除外・昇順）を決定。ESM（Pro エコシステムまたは `+esm`/`~esm`）のみの修正には `esm: true` を付与。影響なし（該当行なし）は `not-affected` を推定せず記録しない（H4）。キーの順序は `cve, status, fixedVersions, esm?, osvIds`。スナップショット不足時は警告を発して除外。
    - `buildDistroSources`: catalog の `distroSources` から `_source` を構築。Debian / Ubuntu の `recordCount` は採用された全 CVE の一意な OSV ID 数、`retrievedAt` は各系統の最新 `fetchedAt`。endoflife.date の `recordCount` はリリース数。定義の欠落や license 不正時は例外を送出。
  - `scripts/advisories/lib/distro.mjs`:
    - `DISTRO_SECTION_MAX_BYTES = 800 * 1024` を定義・export。
    - `validateDistroSection`: `advisories` と `_source` の相互必須チェック、`_source` の要素・URL・ライセンスチェック、`advisories` のリリースキー・パッケージキー・各 CVE エントリ（項目制限、形式、fixed/open と fixedVersions の整合性、esm の妥当性、OSV ID 形式）を厳格に検証。また distro 節のサイズが 800 KB を超えた場合に例外を送出。
  - `scripts/advisories/build-db.mjs`:
    - `loadUpstream`: `osv-distro` ディレクトリからスナップショットを `upstream.osvDistro` に読み込み。
    - `buildDatabase`: `distro` 節生成時に `buildDistroAdvisories` と `buildDistroSources` を呼び出し、`releases, map, advisories, _source` の順で格納して `validateDistroSection` で検証。`sources` 配列に distro 節存在時のみ OSV (Debian / Ubuntu) を追加。
    - CLI `--check`: コミット済み DB が distro 節を持つ場合、差分比較前に `validateDistroSection` を実行して原因を出力するよう実装。
  - `scripts/advisories/fetch-upstream.mjs`:
    - 引数に `distroMap` を追加。`args.distroOnly` 時および通常の週次取得（`!args.only`）時に `fetchOsvDistro` を実行し、`osvDistroTargets` の各エコシステム・パッケージを取得・圧縮して `upstream/osv-distro/` に保存。manifest に `osv-distro:<eco>:<name>` を記録。
  - `scripts/ci/check-size.mjs`:
    - `SIZE_LIMITS.distro = 800 * 1024` を追加。
    - `checkSizes`: DB が JSON としてパース可能かつ `distro` 節を持つ場合に `target: 'distro'` のサイズ検査（80% で warn、上限超で fail）を追加。
  - `src/shared/types.ts`:
    - `DistroAdvisoryStatus`, `DistroAdvisoryEntry`, `DistroSourceRecord` を追加し、`AdvisoryDistroSection` に任意の `advisories`, `_source` を追加。
  - `tests/` は一切変更せず、型検査（`npx tsc --noEmit`）および構文検査が通ることを確認。
- 外部の事実:
  - 設計メモ（T05.md）の「外部の事実」に記載された一次資料に基づく値（OSV エコシステム名、レコード形式、ライセンス値等）のみを使用。
- 未解決: なし

## T06 設計  (2026-11-16 01:10)
- 変更ファイル: docs/dev/v1.8.1/design/T06.md（新規）, tests/distro-advisory.test.ts（新規）, tests/distro-advisory-report.test.ts（新規）, tests/distro-release-display.test.ts（新規）, tests/distro-release-display-callers.test.ts（新規）。固定 DB と既存テストは変えていない
- 判断したこと:
  - CVE ごとの判定は新しい純粋関数 `assessDistroAdvisories`（src/detection/distro-advisory.ts）にし、engine が技術に `distroAdvisories` を付ける。照合の区分（`advisoryMatchStatus: 'Needs Review'`・`advisories: []`）と `SEC-CVE` は第1段階のまま変えない（H4）。
  - 「要確認件数」は `summary.requiresAttentionCount`、「バッジ」は拡張のアイコンの数字（`updateBadge`）と解釈した。第1段階のディストリ版は指摘を作らないので、H4a の「それ以外は件数に入れる」を満たすため、数える区分（not-fixed・open・unknown-revision・no-data）の CVE がある技術ごとに新しい指摘 `SEC-DISTRO-CVE-<技術>`（warning・LOW）を 1 件出す。CVE ごとに指摘を作らない（警告を増やしすぎない）。CVE の内訳は `reviewCount` で画面とエクスポートに出す。
  - ディストリにだけある CVE は、§4.1 のとおり not-fixed だけ並べて数え、fixed は「ほかにディストリで修正済み N 件」の件数だけにした。open・not-affected・パッケージ版が無いときのものは並べない。
  - fixed は「パッケージ版がすべての修正版以上」のときだけ（T05 の解釈 3 を受けた安全側）。比べられない版は unknown-revision。悪いほうの順は not-fixed > open > unknown-revision > no-data > fixed > not-affected。
  - `distro.advisories` が無い DB（固定 DB・T02 までの DB）では判定しない（§5.3 を当てはめた）。これで既存テストの期待値は変わらない。パッケージ版は `DistroInference.packageVersion` として推定の結果に持たせる（PHP の `-4ubuntu2.19` などの接尾辞があるときだけ）。
  - 表示名の共通化は `src/shared/distro-display.ts` の `formatDistroReleaseDisplay`。`inf.release` を優先し、`eolInfo.label` は OS のライフサイクル由来（`source` で見分ける）のときだけ使う。T03 の `judgeDistroEol` の名前の組み立ても同じ関数に寄せる（1 か所だけ）。4 つの出力経路が呼んでいることは、`vi.mock` で目印に差し替える振る舞いのテストと、ソースの静的な確認の両方で確かめる。
  - expectRed: 実装の前に、tests/distro-advisory-report.test.ts は 46 件中 30 件が機能が無いため（`distroAdvisories` が無い、`SEC-DISTRO-CVE` が無い、接頭辞が無い、表示が無い）失敗した。通る 16 件は前提・陰性（固定 DB で出さない、第三者で使わない）の確認。ほかの 3 ファイルは新しいモジュール（distro-advisory・distro-display）が無いため読み込みで失敗した。test-hygiene は通る。型検査の失敗は、新しいモジュールと型の項目が無いことによるものだけ（テスト側の型の誤り 1 件は直した）。
  - 一時ディレクトリに参照実装を置いて型検査と実行を確かめることは、夜間の権限でできなかった。設計メモの規則とテストの期待値を 1 件ずつ突き合わせた。
- 外部の事実:
  - 新しく Web から取った値は無い。OSV の `fixed` イベントの意味（版 ≧ fixed なら影響の範囲外）を https://ossf.github.io/osv-schema/ で確かめた（2026-11-16）。版の比較は T01（Debian Policy 5.6.12）、データの形は T05 の設計メモのとおり。
- 未解決:
  - H4a により、同梱 DB に `distro.advisories` がある状態では、Ubuntu / Debian の Apache・nginx（パッケージ版が取れず unknown-revision になる）でも、上流の CVE が 1 件以上あれば LOW の指摘が 1 件増え、第1段階より要確認件数が 1 増える。§4.2 の「数える（第1段階と同じ）」を「区分の扱いは第1段階と同じ Needs Review で、件数には入れる」と読んだ結果。人が「第1段階と同じく指摘を増やさない」と判断する場合は、unknown-revision・no-data だけの技術では指摘を出さないよう設計とテストを直す。
  - ディストリにだけある open の CVE（Ubuntu の needs-triage・deferred など）は、§4.1 のとおり照合の対象外にした（並べず数えない）。修正版の無い CVE を件数として示すかは人の判断。

## T06 実装  (2026-11-16 01:25)
- 変更ファイル: src/shared/types.ts, src/shared/distro-display.ts（新規）, src/detection/distro-advisory.ts（新規）, src/detection/distro-inference.ts, src/detection/advisory.ts, src/detection/engine.ts, src/background/service-worker.ts, src/popup/render.ts, src/dashboard/render.ts, src/export/markdown.ts, src/export/csv.ts, docs/DETECTION_SPECIFICATION.md
- 判断したこと:
  - リリース表示名の共通化: `src/shared/distro-display.ts` を新規作成し、`formatDistroReleaseName`（6系統対応、LTSサフィックス対応）、`formatDistroConfidenceJp`、`formatDistroReleaseDisplay`（`inf.release` 優先、OSライフサイクル由来 label 優先、候補連結、第三者・none は「推定なし」）、`formatDistroCveStatusLabel`（6区分の日本語＋英名ラベル）を実装した。popup, dashboard, markdown, csv の 4 経路および `distro-inference.ts` から表示名組み立てロジックを移行し、`BUILDERS` の文字列が `shared/distro-display.ts` 以外に残らないようにした。
  - パッケージ版の抽出: `src/detection/distro-inference.ts` において、ヘッダーの製品トークン接尾辞が `/^-[0-9A-Za-z.+~]+/` に合致する場合に `parseDpkgVersion` を通して revision が空でない場合に `packageVersion` として保持するようにした。Server ヘッダーの括弧内 OS 名のみの場合には付与しない。
  - CVE ごとのディストリ判定: `src/detection/distro-advisory.ts` を新規作成し、`assessDistroAdvisories` を実装。上流の SemVer 比較（`version-matcher`）は一切 import せず、`compareDpkgVersions` のみを用いて Debian / Ubuntu の 6 区分判定を実施した。固定 DB や第三者・バックポート、確信度 none、RHEL 系では判定せず null を返すようにした。候補が複数の場合は悪いほうの順（not-fixed > open > unknown-revision > no-data > fixed > not-affected）で採用し、分かれた場合は `split: true` と `splitNote` を生成。ディストリ限定 CVE は not-fixed のみ並べて数え、fixed は `otherFixedCount` として集計した。
  - 上流 CVE 取得と engine 結合: `src/detection/advisory.ts` に `listUpstreamAdvisoryCves` を追加し、`src/detection/engine.ts` で `assessDistroAdvisories` を呼び出して `tech.distroAdvisories` を付与した。
  - 診断項目と要確認件数: `src/background/service-worker.ts` の `HEADER_DEPENDENT_CHECK_PREFIXES` に `'SEC-DISTRO-CVE-'` を追加し、`tech.distroAdvisories && tech.distroAdvisories.reviewCount > 0` の場合に技術単位で `SEC-DISTRO-CVE-<技術名の大文字>`（warning / LOW）を 1 件生成するようにした。
  - 表示・エクスポート: ポップアップ、ダッシュボード、Markdown、CSV、JSON に区分・修正版・ESM・分かれ注記・他修正済み件数を出力。CSV には列「ディストリの判定」を追加した。
  - 判定・文言には「該当なし」「安全」「Not Affected」「影響はありません」の禁止語を一切含めず、静的検査 C18 も PASS を確認した。
  - 仕様書 `docs/DETECTION_SPECIFICATION.md` に §6.5 として `distroStatus` の仕様を追記した。
  - `tests/` は一切変更せず、型検査（`npx tsc --noEmit`）が通ることを確認した。
- 未解決:
  - 設計メモの未解決事項（H4a による要確認件数・指摘の増加、ディストリ限定 open の扱い）は設計と確定テストに従って実装。人間による確認待ち。


## T07 設計  (2026-11-16 12:36)
- 変更ファイル: docs/dev/v1.8.1/design/T07.md（新規）, tests/https-only-headers.test.ts（新規）, tests/test-server-pages.test.ts（新規）
- 判断したこと:
  - 「対象外」に当たる status は `SecurityStatus` に無い（pass・warning・fail・info・unknown だけ）ので、`'not-applicable'` を新設する（runtimeStatus・coverage と同じ綴り）。ポップアップ・ダッシュボードのラベルは「対象外」、プレーン・Markdown の表記は `N/A`（テストは字面ではなく、ほかの status と区別でき太字でないことを見る）。要確認件数・CRITICAL〜LOW・INFO・UNKNOWN・バッジに数えず、`securityFindings.notApplicable`（任意の項目）に数える。
  - 対象は HTML の仕様で non-secure context なら既定のポリシーを使う COOP と COEP。CORP と Permissions-Policy は secure context の条件が無いので対象外にしない。HSTS は既存のまま。HTTP のページでは COOP は値にかかわらず `SEC-COOP-01` を対象外で 1 件、COEP はヘッダーがあるときだけ対象外で 1 件（COEP は既定で推奨しないため、無ければ項目なし）。
  - 未観測のときは、既存の SPEC-01 の上書き（`HEADER_DEPENDENT_CHECK_PREFIXES`）が対象外より後に動くので unknown が優先される。この順番を変えないよう設計メモに書いた。
  - test-server は、サーバーを起動しない単体テストのために `createRequestHandler`・`TEST_PAGES`・`getStartupLines` を export し、直接実行したときだけ listen する形にする。新しいページは 10 件（WAF 2、SRI 1、ディストリのバナー 6、HTTPS 専用ヘッダー 1）。
  - ディストリのバナーの版は、ハンドラーが対応表から規則（`entries` の順で最初に apache と php の両方があるリリースの `upstreamVersions[0]` など）で選ぶ。合成の対応表を渡すテストで、版が対応表から来ていることを確かめる。対応表に無い版は、Ubuntu の Apache の版の最後の数字を、対応表に無くなるまで増やして作る。
  - `scripts/report-lint.mjs` の `expectedMarkdownStatusBadge` に `not-applicable` を足す必要がある（足さないと http.badssl.com のスナップショットのテストが R02 で落ちる）。実装の方針に書いた。
  - expectRed: tests/https-only-headers.test.ts は 41 件中 21 件が機能が無いため失敗（通る 20 件は HTTPS の v1.8.0 と同じ結果・陰性・未観測の unknown）。tests/test-server-pages.test.ts は 59 件すべてが export が無いこと・import で listen することで失敗（listen はテストで空の関数に差し替え、ポートは開かない）。テストの側の誤りが無いことは、`.agy-out/` に一時的に置いた test-server の試作に向けて実行し、`src/` の対象外が要る 1 件を除く 58 件が通ることで確かめた（試作は消した）。型検査の失敗は `'not-applicable'` と `notApplicable` が型に無いことによる 4 件だけ。test-hygiene は通る。
- 外部の事実:
  - COOP・COEP の non-secure context の扱い: https://html.spec.whatwg.org/multipage/browsers.html#the-coop-headers 、#the-coep-headers（2026-11-16）。CORP: https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header （2026-11-16）。Permissions-Policy: https://w3c.github.io/webappsec-permissions-policy/ （2026-11-16）。Reporting-Endpoints: https://w3c.github.io/reporting/#process-header （2026-11-16）。
  - Bootstrap 5.3.9 の jsDelivr の URL と integrity: https://getbootstrap.com/docs/5.3/getting-started/introduction/ 、配布物の一覧: https://getbootstrap.com/docs/5.3/getting-started/contents/ （2026-11-16）。
  - WAF のヘッダー（cf-mitigated、x-amzn-waf-action）と Debian・sury の版の書式は v1.8.0 T04・v1.8.1 T03 の設計メモの根拠をそのまま使った（新しく取った値は無い）。
- 未解決:
  - Reporting-Endpoints も secure context が条件だが、独立したチェックが無く、関係する `SEC-CSPX-REPORT-01` は CSP の `report-to` の名前の不一致を見るものなので、今回は対象外にしなかった。HTTP のページで対象外にするかは人の判断。
  - HTTP のページでは、COOP の項目が INFO から対象外に移るため、HTTP のサイトの `securityFindings.info` が以前の版の履歴より 1 少なくなる（差分では status の変化として出る）。H6 の決定どおり。

## T07 実装  (2026-11-16 12:50)
- 変更ファイル: src/shared/types.ts, src/shared/security-status.ts, src/security/headers.ts, src/popup/popup.css, src/dashboard/dashboard.css, scripts/report-lint.mjs, docs/DETECTION_SPECIFICATION.md, test-server/server.mjs
- 判断したこと:
  - 設計メモ（T07.md）の「実装の方針」に従い、`SecurityStatus` に `'not-applicable'` を追加し、`InspectionReport['summary']['securityFindings']` に任意プロパティ `notApplicable?: number;` を追加した。
  - `src/shared/security-status.ts`:
    - `summarizeSecurityChecks` で `check.status === 'not-applicable'` の件数を数え、`securityFindings.notApplicable` として常に数値で返すようにした。INFO や UNKNOWN、要確認件数・重大度内訳には含めない。
    - `formatPlainStatusCode` および `formatMarkdownStatusBadge` に `'not-applicable'` の分岐を追加し、`N/A` を返却（太字なし）。
    - `getSecurityCheckDisplayBadge` で `check.status === 'not-applicable'` のとき `{ badgeClass: 'sev-not-applicable', dashLabel: '対象外', popupLabel: '対象外', statusCode, markdownBadge }` を早期リターン。
  - `src/popup/popup.css`, `src/dashboard/dashboard.css`: `.sev-not-applicable` を `.sev-unknown`, `.sev-info` と同じスタイル規則に追加。
  - `src/security/headers.ts`:
    - `!isHttps` の場合、COOP は設定値にかかわらず `SEC-COOP-01`（status: `not-applicable`, severity: `info`, observed: `coop ?? 'ヘッダー未設定'`) を 1 件生成。文言に「HTTPS」を含め、ブラウザが無視するため評価対象外であることを明記。
    - COEP はヘッダーが存在し、かつ `!isHttps` の場合に `SEC-COEP-01`（status: `not-applicable`, severity: `info`, observed: `coep`) を 1 件生成。未設定時は項目を生成しない。
    - CORP、X-Frame-Options、HSTS など他のチェックは変更せず、`isHttps === true` の判定ロジックも既存のまま維持。
  - `scripts/report-lint.mjs`: `expectedMarkdownStatusBadge` に `case 'not-applicable': return 'N/A';` を追加。
  - `docs/DETECTION_SPECIFICATION.md`: ステータス表記および COOP・COEP の診断仕様に `not-applicable`（対象外）の扱いを追記。
  - `test-server/server.mjs`:
    - 単体テスト向けに `createRequestHandler`、`TEST_PAGES`、`getStartupLines` を named export し、`process.argv[1]` と `import.meta.url` の実パス比較（`fs.realpathSync`）により直接実行時のみ listen するように分離。
    - `TEST_PAGES` に既存 11 ページと新しい 10 ページ（WAF 2、SRI 1、ディストリ 6、HTTPS 専用 1）の計 21 ページを定義。
    - `createRequestHandler` で `options.distroMap`（省略時は `data/advisories/distro-map.json`）を読み込み、設計メモの規則に従って Ubuntu / Debian / RHEL / 対応表外のバージョンとリリース番号を抽出してヘッダーおよび HTML 本文（各パス名を含む）を動的に生成するハンドラーを実装。
    - `/waf-cloudflare-challenge` は 403 および `cf-mitigated: challenge`、`/cdn-cgi/challenge-platform/` へのスタブ応答を返し、`/waf-aws-captcha` は 405 および `x-amzn-waf-action: captcha` を返却。
    - `/sri-cdn` は設計メモの事実表に従い Bootstrap 5.3.9 の jsDelivr URL（integrity あり・なし各 2 件）を含む HTML を返却。
    - `/https-only-headers` は COOP と COEP を返却。
  - 文言に「安全」「該当なし」を含めず、secure context は「HTTPS のページ」「secure context（HTTPS）」として記述。
  - `tests/` は一切変更せず、型検査（`npx tsc --noEmit`）がエラーなく通ることを確認。
- 外部の事実:
  - 設計メモ（T07.md）の「外部の事実」に記載された一次資料に基づく値（WHATWG HTML の COOP/COEP secure context 要件、Bootstrap 5.3.9 jsDelivr URL および SRI ハッシュ値、WAF ヘッダー仕様等）のみを使用。
- 未解決: なし
