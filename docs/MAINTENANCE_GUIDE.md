# Web Technology & Security Inspector - 保守・リリース運用ガイド

本書は、『Web Technology & Security Inspector』のバージョンアップ手順、内蔵オフライン脆弱性データベース（`advisory-db.json`）の更新手順、配布用パッケージ作成・ストア申請フロー、および診断レポートの一括取得スクリプト・整合性チェッカーの運用手順をまとめた開発者・メンテナー向け運用ガイドです。

---

## 1. バージョンアップの仕組みと手順

### 1.1 バージョン管理の仕組み

本拡張機能では、ブラウザの Manifest V3 仕様および npm の慣例に基づきバージョンを管理しています。

```mermaid
flowchart TD
    subgraph MasterSources ["マスターデータ (設定ファイル)"]
        Manifest["public/manifest.json<br>(Chrome / Edge が認識する本体バージョン)"]
        Pkg["package.json<br>(npmおよびZIP作成スクリプトが認識)"]
    end

    subgraph AutoReflect ["自動反映される箇所 (コード修正不要)"]
        PopupBadge["ポップアップ画面のバージョンバッジ<br>(chrome.runtime.getManifest().version)"]
        DashBadge["ダッシュボード画面のバージョンバッジ<br>(chrome.runtime.getManifest().version)"]
        ZipFile["配布用ZIPファイル名<br>(release/web-inspector-vX.X.X.zip)"]
    end

    subgraph SyncNeeded ["手動で更新が必要な関連ファイル"]
        Rules["src/detection/rules/index.ts<br>(RULES_VERSION 定数: レポート出力用)"]
        SW["src/background/service-worker.ts 等<br>(EXTENSION_VERSION フォールバック)"]
        HTML["popup.html / dashboard.html<br>(JS実行前の初期HTMLテキスト)"]
        Docs["README.md / ドキュメント<br>(バッジ・見出しの表記)"]
    end

    Manifest --> AutoReflect
    Pkg --> AutoReflect
    MasterSources -.->|整合性維持| SyncNeeded
```

- **画面バッジの自動取得**: ポップアップ画面やダッシュボード画面のバージョンバッジ（`v1.7.1` 等）は、実行時に `chrome.runtime.getManifest().version` から動的に読み込まれます。
- **ZIPファイル名の自動連動**: `npm run package` 実行時、`scripts/package.mjs` が `package.json` の `version` を読み取り、自動的に `release/web-inspector-v{version}.zip` を出力します。

---

### 1.2 バージョン変更時の更新対象ファイル・チェックリスト

バージョン（例: `1.7.0` $\rightarrow$ `1.7.1`）を変更する際は、以下のファイルを更新します（※ `src/popup/popup.html` および `src/dashboard/dashboard.html` は v1.7.0 で廃止され、ルート直下の `popup.html` / `dashboard.html` に一本化されました。また、オフライン脆弱性 DB のスキーマ互換性が変わらないマイナー・パッチ更新では、`src/detection/advisory-db.json` の `minExtensionVersion` は `"1.7.0"` のまま変更しません）。

| No | ファイルパス | 役割・更新内容 | 必須区分 |
|:---:|---|---|:---:|
| 1 | [`public/manifest.json`](../public/manifest.json) | `"version": "X.X.X"`（Chrome Web Store認識用） | **【必須】** |
| 2 | [`package.json`](../package.json) / [`package-lock.json`](../package-lock.json) | `"version": "X.X.X"`（ZIP出力スクリプト・npm管理用） | **【必須】** |
| 3 | [`src/detection/rules/index.ts`](../src/detection/rules/index.ts) | `export const RULES_VERSION = 'X.X.X';`（レポート記録用） | **【必須】** |
| 4 | [`src/background/service-worker.ts`](../src/background/service-worker.ts) | `EXTENSION_VERSION` のフォールバック文字列 | 推奨 |
| 5 | [`src/popup/popup.ts`](../src/popup/popup.ts) / [`src/dashboard/dashboard.ts`](../src/dashboard/dashboard.ts) | `setupVersionBadge()` のフォールバック文字列 | 推奨 |
| 6 | [`src/export/markdown.ts`](../src/export/markdown.ts) / [`src/export/csv.ts`](../src/export/csv.ts) | レポート出力時の `extensionVersion` フォールバック文字列 | 推奨 |
| 7 | [`popup.html`](../popup.html) | `<span id="brandVersion">vX.X.X</span>` 初期HTMLテキスト（ルート直下に一本化） | 推奨 |
| 8 | [`dashboard.html`](../dashboard.html) | `<span id="dashboardVersion">vX.X.X</span>` 初期HTMLテキスト（ルート直下に一本化） | 推奨 |
| 9 | [`README.md`](../README.md) / [`docs/DETECTION_SPECIFICATION.md`](./DETECTION_SPECIFICATION.md) | バッジ（`version-X.X.X-blue.svg`）・対象バージョン・機能一覧見出し | 推奨 |

---

### 1.3 バージョンアップ作業フロー

```mermaid
sequenceDiagram
    autonumber
    actor Dev as 開発者
    participant Git as 作業ブランチ
    participant Test as Vitest (npm test)
    participant Pack as npm run package
    participant Store as Chrome Web Store

    Dev->>Git: 上記チェックリストのファイルを新バージョンに更新
    Dev->>Test: npm test を実行 (全テスト合格確認)
    Test-->>Dev: All Passed (320+ tests)
    Dev->>Pack: npm run package を実行
    Pack->>Pack: ① 脆弱性DBの整合性検証 (validate)
    Pack->>Pack: ② Vite本番バンドル (build)
    Pack->>Pack: ③ release/web-inspector-vX.X.X.zip の生成
    Pack-->>Dev: パッケージ完成
    Dev->>Store: デベロッパーダッシュボードにZIPをアップロード申請
```

---

## 2. 脆弱性データベース (advisory-db) の更新手順

### 2.1 オフラインDBの仕組みと更新日自動反映

本拡張機能は、プライバシー保護と高速動作のため、閲覧先URLや検出技術を外部APIへ送信しません。拡張機能に内蔵された静的スナップショットDB（`src/detection/advisory-db.json`）を用いて**完全ローカル突合**を行います。

```mermaid
flowchart LR
    subgraph UpdatePhase ["更新フェーズ (開発環境)"]
        SyncCmd["npm run advisories:sync"] --> Fetch["OSV / NVD / endoflife.date API<br>から最新アドバイザリを取得"]
        Fetch --> AutoGen["advisory-db.json を生成<br>・dataVersion: YYYYMMDD<br>・generatedAt: ISO日時"]
        AutoGen --> ValCmd["npm run advisories:validate<br>(スキーマ・2MB上限チェック)"]
    end

    subgraph RuntimePhase ["実行フェーズ (ブラウザ内部)"]
        Load["拡張機能がDBメタデータを動的取得<br>(getAdvisoryDbMetadata())"]
        Load --> DispDate["画面上の表示日付が自動更新<br>🛡️ 脆弱性DB更新日: YYYY-MM-DD"]
        Load --> FreshCheck["鮮度自動計算 (31日ルール)<br>・0〜7日: Fresh<br>・8〜30日: Moderate<br>・31日以上: Stale (警告バッジ点灯)"]
    end

    AutoGen --> Load
```

- **コード修正不要**: `advisories:sync` が実行日の日付（例: `20261024`）をメタデータとして自動埋め込むため、画面表示やレポート（Markdown / CSV）の日付を変更するためのソースコード修正は一切不要です。
- **鮮度警告の自動判定**: DBの `generatedAt` から経過日数が動的に計算され、31日を超過すると `⚠️ DB鮮度: 31日以上経過` バッジが自動点灯します。

### 2.2 脆弱性スコア・重大度 採用ポリシー

本拡張機能では、客観的かつ機械的なセキュリティ診断を行うため、以下のスコア採用基準と重大度導出ルールを定めています。手書きによる恣意的な重大度の設定は禁止されています。

#### ① スコア採用の優先順位
1. **第一優先 (Primary)**: NIST NVD (`nvd@nist.gov`) の公式評価「Type: Primary」の CVSS v3.1 ベーススコアを採用する。
2. **第二優先 (Secondary)**: NVD の Primary 評価が存在しない場合は、CISA-ADP（Cybersecurity and Infrastructure Security Agency Automated Data Processing）または CNA（CVE Numbering Authority）の評価を採用する（評価主体ラベルは「CISA-ADP」と明記する）。
3. **第三優先 (Fallback)**: NVD に CVSS v3.x が登録されていない場合は、GitHub Advisory Database (GHSA) の公式スコアを採用する。
※ CVSS v3.1 と v4.0 が併記されている場合は、エコシステムの互換性維持のため **CVSS v3.1 を優先** します。

#### ② 重大度 (Severity) の機械的導出ルール
重大度はスコア値から以下の閾値に基づき機械的に導出します：
- **`CRITICAL`**: CVSS スコア 9.0 〜 10.0
- **`HIGH`**: CVSS スコア 7.0 〜 8.9
- **`MEDIUM`**: CVSS スコア 4.0 〜 6.9
- **`LOW`**: CVSS スコア 0.1 〜 3.9

#### ③ 評価乖離時の透明性
Primary 評価と Secondary（CISA-ADP 等）評価の間で重大度レベルに乖離がある場合（例: Primary 9.8 Critical に対し Secondary 7.5 High など）、Primary のスコアを採用した上で、`scoreSource: "nvd@nist.gov (Primary)"` と記録し、要約・注記欄に `CISA-ADP評価: X.X (重大度)` を併記します。

#### ④ 適用条件のある脆弱性の扱い
特定環境・特定モジュール（例: Windows上のPHP-CGI、Apacheのmod_lua、Node.jsの実験的パーミッションモデルなど）が有効化されている場合のみ成立する脆弱性は、バージョン単体で断定せず、データ側の文面（要約・根拠）に `該当の可能性あり (条件: ○○)` を必ず明記します。

---

### 2.3 脆弱性DBおよびPublic Suffix List (PSL) の更新手順（ステップ・バイ・ステップ）

> **v1.6.6 / v1.7.0 以降の更新方式 (自動化):** 脆弱性DBは GitHub Actions `Advisory DB Update` (毎週月曜 05:23 JST) が
> 上流 (OSV / NVD / endoflife.date / CISA KEV) および Public Suffix List (`publicsuffix.org`) から自動取得・生成し、PR を作成します。
> v1.7.0 からは `wordpress`, `php`, `nginx`, `apache`, `nodejs` の NVD CPE 自動取り込み (`autoIngest: true`) が有効化され、5つの安全ガード（サードパーティプラグインCPE除外、上限なし`*`のみのcriteria除外、Rejected/Disputed除外、対象年フィルタ、製品あたり件数上限）を経て `minExtensionVersion: "1.7.0"`・`fixStatus`（`'fixed' | 'unfixed' | 'unknown'`）・`kev` フラグ付きで生成されます。
> 設計・必要な設定・段階的な有効化は [レビュー結果・開発指示書 第5章](./REVIEW_v1.6.5.md) および本ガイド第3.2節を参照してください。
> `src/detection/advisory-db.json`、`data/advisories/build-report.json`、`src/security/psl-rules.generated.ts` は手編集禁止です (CI の `build-db.mjs --check` および `spec-integrity.test.ts` で検出されます)。
> 人手で管理するデータは `data/advisories/catalog.json` (対象製品・取得元・`autoIngest`設定) と `data/advisories/curated.json` (レビュー済みエントリ・除外・静的EOL) です。

#### ステップ 1: 最新アドバイザリおよび PSL の同期 (ローカルで手動実行する場合)
```bash
npm run advisories:fetch   # 上流スナップショット + PSL (data/psl/public_suffix_list.dat) 取得 (要ネットワーク)
npm run advisories:build   # スナップショットから advisory-db.json を決定的に生成
npm run spec:generate      # 仕様書カタログ・README表・DOMセレクタ・PSL定義 (psl-rules.generated.ts) を再生成
npm run advisories:diff    # origin/main との差分と分類 (none / minor / major)
```
- `advisories:sync` は上記 fetch → build → validate を連続実行します。
- `data/psl/public_suffix_list.dat` が未取得の環境では、`npm run spec:generate` は警告を出力した上でフォールバック PSL 一覧（日本の47都道府県・政令指定都市JPドメインを含む）を使用し、ビルドを止めません。

#### ステップ 2: DBの整合性・サイズ検証
```bash
npm run advisories:validate
```
- スキーマ構造、バージョン範囲の書式、ファイルサイズが2MB以内（拡張機能の軽量性維持）であることを自動検証します。

#### ステップ 3: 単体テストの実行
```bash
npm test
```
- 脆弱性突合ロジックやバージョン判定テストがすべてパスすることを確認します。

#### ステップ 4: NVD 一次情報・CPE との機械的照合検証
```bash
npm run advisories:verify-nvd
# またはオンライン直接取得: node scripts/verify-advisories-nvd.mjs --online
```
- NVD の Primary CVSS スコアおよび CPE バージョン範囲と全件自動突合し、未解決差異が 0 件であることを確認します。

#### ステップ 5: 新しいDBを内包したZIPパッケージの作成
```bash
npm run package
```
- 検証、ビルド、ZIP圧縮が一括で実行され、`release/web-inspector-vX.X.X.zip` が生成されます。

---

### 2.4 NVD CPE 照合検証・既知の逸脱および凍結基準 (Freeze Criteria)

本拡張機能では、手作業による恣意的な判定の排除と継続的再現性を保証するため、NVD の CPE 定義と機械的に照合する検証スクリプト（`scripts/verify-advisories-nvd.mjs`）を運用しています。

#### ① 凍結基準 (Freeze Criteria)
リリース前、および週次 CI ジョブにおいて、以下の基準が満たされていることを**凍結条件**とします：
1. **完全照合性**: 脆弱性DBの全エントリについて、`scripts/verify-advisories-nvd.mjs` の実行結果が `[PASS]`（終了コード 0、未解決差異 0 件）であること。
2. **逸脱の限定適用と期待値検証**: 既知の逸脱（許可リスト）は**実際に NVD CPE と差異がある場合のみ適用**され、一致するエントリ（AngularJS 7676 や WordPress 21661 等）は自動的に `MATCH` と判定されること。また、許可リストに登録された `expectedDbRange` および `expectedNvdRange` と完全一致し、公式根拠となる `sourceUrl`（ベンダー公式アドバイザリ等）が必須記載されていること。

#### ② 既知の逸脱一覧 (Known Deviations from NVD CPE)

※ WordPress CVE-2022-21661 (22ブランチ網羅)、nginx CVE-2023-44487 (`>= 1.9.5, < 1.25.3`)、AngularJS CVE-2020-7676 は NVD CPE と完全一致（`MATCH`）したため逸脱から除外されました。

| CVE | ソフトウェア | DB range (期待値) | NVD range (期待値) | 分類 | 公式根拠・採用理由 | 出典 URL |
|---|---|---|---|---|---|---|
| **CVE-2023-39332** | Node.js | `>= 20.0.0, < 20.8.1` | `>= 20.0.0, < 20.8.0` | ベンダー公式優先 | Node.js公式セキュリティリリース(2023-10-13)において20.8.1でパッチ提供。NVD CPEは`< 20.8.0`で登録されているが、20.8.0も脆弱であるためベンダー公式パッチバージョンを優先採用。 | [Node.js Security Release](https://nodejs.org/en/blog/vulnerability/october-2023-security-release) |
| **CVE-2024-4577** | PHP | `< 8.1.29 \|\| ...` | `>= 8.1.0, < 8.1.29 \|\| ...` | 安全側包括 (EOL連動) | EOLのPHP 8.0以前は公式パッチ未提供だが、Windows上のPHP-CGI環境では本脆弱性に該当する。DBでは安全側に倒して`< 8.1.29`として検知対象に含めEOL判定と併せて更新を促す。NVD CPEはパッチ提供ブランチである`>= 8.1.0`から定義。 | [PHP Security Advisory](https://www.php.net/archive/2024.php#2024-06-06-1) |
| **CVE-2021-3129** | Laravel | `< 8.4.3` | `< 2.5.2` (Ignition) | 連動パッケージ置換 | NVD CVE-2021-3129 の configurations において、`cpe:2.3:a:facade:ignition < 2.5.2` (vulnerable: true) と `cpe:2.3:a:laravel:laravel < 8.4.2` (vulnerable: false) が連動ノードとして定義。Laravel 8.4.3 で ignition 2.5.2 以降に依存引き上げが行われたため、本体バージョン `< 8.4.3` としてマッピング。<br/>**※【既知の制約】**: 本脆弱性はデバッグページライブラリ `facade/ignition` の脆弱性であり、`< 8.4.3` はアプリ雛形 (`laravel/laravel`) の番号体系です。Web Inspector が外部から受動検出するのはフレームワークや Cookie であり、外部からバージョンが特定されないため実環境ではほぼ発火しません。次期版でエントリの是非を見直し、Ignition デバッグページの直接検出等への移行を検討します。 | [NVD CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129) |
| **CVE-2022-25869** | AngularJS | `<= 1.8.3` | `(CPE未定義)` | GHSA 主導エントリ | NVDにCVSSスコア(6.1)は登録されているがCPE該当範囲情報が未定義のため、一次情報としてGitHub Advisory Database (GHSA-prc3-vjfx-vhm9: `<= 1.8.3`) を採用。EOLのため公式パッチなし (fixedVersion: null)。 | [GHSA-prc3-vjfx-vhm9](https://github.com/advisories/GHSA-prc3-vjfx-vhm9) |

---

### 2.5 公開中バージョン (v1.3.3) における過去の脆弱性DB誤記一覧

v1.6.4 への改訂に伴う NVD CPE 機械的突合により、公開中バージョン (v1.3.3) に存在していた以下の不正確なエントリが特定され、是正・除外されました。

1. **Vue.js CVE-2020-13426 の誤登録 (除外)**:
   - 1.3.3 では `CVE-2020-13426` が「ReDoS in vue template compiler (< 2.6.10)」として登録されていましたが、NVD の一次情報では WordPress のサードパーティプラグイン「Multi-Scheduler」の CSRF 脆弱性であることが判明しました。Vue.js 本体とは無関係のため除外しました（Vue 2 系は全件 EOL として保護）。
2. **WordPress CVE-2023-32243 の誤登録 (除外)**:
   - WordPress 本体ではなくサードパーティプラグイン「Essential Addons for Elementor」の脆弱性であったため除外。
3. **React CVE-2018-6341 の範囲過不足 (是正)**:
   - 1.3.3 の `< 16.0.0` から、NVD CPE 通りの 16 系 SSR 5 ブランチ (`>= 16.0.0, < 16.0.1 || ...`) に是正。
4. **nginx CVE-2021-23017 の範囲過剰 (是正)**:
   - `< 1.21.0` から、修正版 1.20.1 を除外した `>= 0.6.18, < 1.20.1` に是正。
5. **PHP CVE-2022-31628 の種別・重大度・範囲誤記 (是正)**:
   - 「Pharデシリアライズ・High(7.5)」から、NVD一次情報通りの「DoS(gzip展開無限ループ)・Medium(5.5)」および複数ブランチ網羅に是正。
6. **Lodash CVE-2021-23337 のタイトル混同 (是正)**:
   - 「プロトタイプ汚染」から「コマンドインジェクション (_.template)」に是正。
*(※なお、Node.js CVE-2022-35255 や Laravel CVE-2021-3129、AngularJS CVE-2022-25869 は 1.3.3 には存在せず、v1.4.0 以降の機能拡張で新設されたエントリです)*

---

### 2.6 NVD CPE 範囲と semver 表記の同一視規則

NVD の CPE criteria はベンダー提供の版数記法（`versionEndIncluding` / `versionEndExcluding`）に基づいており、semver 上で以下の等価性規則を適用して機械照合を行っています。

1. **離散バージョンにおける上限等価性**:
   - リリース間に中間バージョンが存在しない場合、`<= X.Y.Z` と `< X.Y.(Z+1)` は実質同一の範囲として扱われます。
   - 例: nginx CVE-2023-44487 において、NVD CPE は `<= 1.25.2` と定義されていますが、公式リリース体系上 1.25.2 の次の版は 1.25.3 であるため、DB の `< 1.25.3` と等価（MATCH）として照合します。
   - 例: Laravel CVE-2018-15133 において、NVD CPE の `<= 5.5.40` は 5.5 系パッチ体系上 `< 5.5.41` と等価として照合します。
2. **商用・別エディション criteria の除外**:
   - NVD の configurations にオープンソース版と商用版（例: F5 NGINX Plus の `r25` 〜 `r29` など）が同一エントリ内に混在している場合、検証スクリプトは本拡張機能が対象とするオープンソース版のバージョン体系（`1.x.x`）の criteria を抽出して突合を行います。

---

### 2.7 既知の退行と修正の記録 (v1.6.5 開発時)

1. **SSR連動推論ヘッダーの許可リストからの脱落と是正 (コミット `dd1fd8a`)**:
   - **事象**: コミット `6f72f60` においてレスポンスヘッダーキャッシュの機密情報保護（許可リスト化）を導入した際、`src/detection/engine.ts` でサーバーサイドレンダリング（SSR）判定のために直接参照されていたヘッダー（`x-nextjs-cache`, `x-nitro-cache`）が許可リストから一時的に脱落し、Next.js / Nuxt / SvelteKit からの Node.js 連動推論が発火しなくなっていた。
   - **発見と修正**: 提出前追加確認 (A1) におけるコード内ヘッダー参照文字列の網羅走査により特定。コミット `dd1fd8a` にて `SSR_INFERENCE_HEADER_NAMES` を定義し、Service Worker の `ALLOWED_RESPONSE_HEADERS` に正式追加・統合した。
   - **影響範囲**: ストア未提出の開発ブランチ作業（コミット `6f72f60`）における内部的な退行であり、公開版（v1.6.4 以前）および利用者への実影響は皆無。
   - **テスト強化の経緯**:
     - 当初作成された単体テスト（A1）は、モックオブジェクト内で直接 `headers: { 'x-nextjs-cache': ['HIT'] }` を設定していたため、変異テスト（`SSR_INFERENCE_HEADER_NAMES` をコメントアウト）を実行した際の初回結果は**緑（PASS）**となってしまい、退行を検知できない脆弱なテストとなっていました。
     - そこで、テスト内で生ヘッダーを必ず `filterAndSanitizeHeaders` に通してからキャッシュモックへ渡すよう改修し、変異時に確実に**赤（FAIL）**となることを実証しました。
     - さらに、回帰防止として以下のテスト群を整備しました：
       - 単体テスト: A1 テスト（キャッシュ経由の Node.js 連動推論）
       - 単体テスト: 3-3 許可リスト期待値テスト（包含ヘッダーおよび除外機密ヘッダーの網羅性アサート）
       - 実機 E2E テスト: `/next-ssr-positive`（SSR 指標経由の Node.js 推論確認）
       - 実機 E2E テスト: `/next-static-negative`（Next.js 本体直接検出あり、かつ SSR 指標なし環境で Node.js が除外されることの確認）
   - **許可リストを変更・追加する際の手順**:
     1. rules (`src/detection/rules/*.json`) に `type: "header"` の `target` を追加した場合、`tests/service-worker.test.ts` の許可リスト期待値テスト（3-3）に期待ヘッダー名を更新・追記する。
     2. SSR 推論などルール外のエンジンロジックで直接参照するヘッダーを追加した場合、`src/detection/rules/index.ts` の `SSR_INFERENCE_HEADER_NAMES` に追加する。
     3. 一時的に該当ヘッダーを除外する変異テストを実行し、テストが赤（FAIL）になることを確認する。

---

### 2.8 既知の制限と将来の課題 (v1.6.6〜v1.7.1 での解消と v1.8.0 以降の検討項目)

#### ① v1.6.6 で解消した制限・不具合
1. **履歴ボタンのインライン onclick 廃止 (IMPL-01)**:
   - イベント委譲方式に刷新し、MV3 拡張ページの CSP 下でダッシュボード履歴の「表示」「削除」が確実に動作するように解消。
2. **ヘッダー未取得時の誤警告とタブURL照合 (SPEC-01, IMPL-02, SPEC-16)**:
   - ヘッダー未取得時は「未観測 (unknown / info)」として安全に扱い、タブ origin 不一致時の誤キャッシュ適用防止およびプリレンダリング（`tabs.onReplaced`）時のキャッシュ移行に対応。
3. **EOL 既定値・解析不能バージョン・実行時値の検証 (SPEC-04, SPEC-06, IMPL-04)**:
   - 「先頭が Supported なら Supported」とする既定動作を廃止し、古い系列は安全側に EOL 扱いとするよう是正。解析不能バージョンでの誤照合防止、MAIN world 戻り値の型・形式検証および DOM 走査上限（200要素）を導入。
4. **ディストリビューション版パッケージにおけるバックポート誤判定の第1段階 (SPEC-02)**:
   - `distroHint` を導入し、Ubuntu/Debian 等の OS 名やパッケージ接尾辞を検出して `Needs Review`（バックポートの可能性あり）として安全側に扱うように是正。
5. **検出ルールの誤検知 (SPEC-09)**:
   - Tailwind CSS（Bootstrap 混同解消）、Font Awesome（all.css 汎用一致解消）、Chart.js（orgchart.js 混同解消）、D3.js（md3.js 混同解消）、Ruby on Rails（Passenger 単独判定解消）を是正。
6. **DOM シグナル収集の到達性確保 (DOC-01)**:
   - ルール定義から DOM セレクタを自動抽出し（`dom-selectors.generated.ts`）、Alpine.js, htmx, Material UI 等の DOM シグナル到達性を全件確保。
7. **主要 JS ライブラリの検出と誤認防止 (DOC-02)**:
   - Lodash および Moment.js の検出ルールを追加し、Underscore.js との誤認防止ガードを実装。
8. **innerHTML への未エスケープ出力解消 (IMPL-03)**:
   - `escapeHtml` を共通化し、`safeHref` による URL プロトコル検証（https: のみ許可）を導入。
9. **旧脆弱性/EOL データベース・エンジンの削除 (DOC-09)**:
   - 旧DBおよび旧エンジンコードを廃止し、`matchOfflineAdvisories()` に一本化。
10. **プライバシーポリシー記述の実装整合 (DOC-08)**:
    - Cookie 値の一時読み込み後の即時破棄、content script の配置方針、webRequest ヘッダー許可リストの保持方針を実装と整合化。

#### ② v1.7.0 で解消した制限・機能強化
1. **SemVer・プレリリース・複数ブランチ範囲の厳密比較と Angular 暫定対応の撤去 (SPEC-03, SPEC-05 / T01, T14)**:
   - 4要素以上のバージョンやプレリリース識別子（`-alpha.1`, `-next.1` 等）の比較規則を刷新し、別メジャーのプレリリース版が過去ブランチの上限条件（`< 19.2.15` 等）に誤一致しないよう是正。これに伴い `curated.json` および `verify-advisories-nvd.mjs` の Angular 暫定対応を撤去。
2. **NVD 自動取り込みの有効化と `fixStatus`・CISA KEV・重大度4段階の表示 (SPEC-12, SPEC-13, SPEC-15, IMPL-09 / T03, T04, T05)**:
   - `wordpress`, `php`, `nginx`, `apache`, `nodejs` の NVD CPE 自動取り込みを有効化し、`minExtensionVersion: "1.7.0"` に更新。
   - `fixStatus`（`fixed` / `unfixed` / `unknown`）、CISA KEV 悪用警告バッジ、重大度4段階（`critical` / `high` / `medium` / `low`）のフィルタ・集計・エクスポート対応、および GHSA 単体エントリの GitHub Advisory リンク生成を実装。
3. **同一技術の複数バージョン保持と全件照合 (SPEC-14 / T06)**:
   - 同一ページ内で複数バージョンが検出された場合に `detectedVersions` として全件保持し、代表 `version` に最小 SemVer を設定して全バージョンを脆弱性・EOL照合する仕様へ強化。
4. **末尾ハイフン付きヘッダーターゲット (`x-fastify-`) の前方一致対応と連動推論の厳密分離 (SPEC-11 / T07)**:
   - `target` が `-` で終わるヘッダーシグナルを前方一致（`startsWith`）で照合するよう修正し、弱い直接証拠（35点等）と連動推論の合算時に `detectionMethod` が誤って `direct` にならないよう分離。
5. **CSP 複数ヘッダー積集合評価・`<meta>` CSP・ヘッダー値妥当性検証・混在コンテンツ拡大 (SPEC-07, SPEC-08, SPEC-10 / T08, T09)**:
   - 複数 CSP ヘッダーの積集合評価、`<meta http-equiv="Content-Security-Policy">` 対応、`script-src-elem` フォールバック、`nonce-`/`sha*` による `'unsafe-inline'` 無効化、HSTS/XCTO/XFO/Referrer-Policy の値妥当性検証、および `srcset`/`object`/`form`/`style` 等の混在コンテンツ検出に対応。
6. **履歴保存の直列化・URLクエリ/ハッシュ除去・`data:`/`blob:` 丸め・許容リスト移行 (IMPL-05, IMPL-06, IMPL-07, IMPL-10 / T10)**:
   - 同時調査時の履歴上書きを防ぐ直列化ロック、履歴・JSON/CSV/Markdown出力からのクエリ文字列・フラグメント除去、`data:`/`blob:`/`javascript:` URL のスキーム丸め、および正規化URLによる許容設定キー移行を実装。
7. **Content Script のオンデマンド動的注入・CHIPS Cookie・重複除去 (IMPL-08, IMPL-11, IMPL-12 / T11)**:
   - `manifest.json` の常時 `content_scripts` を廃止して調査実行時のみの `chrome.scripting.executeScript` 注入に移行し、CHIPS（`Partitioned`）Cookie の取得・評価および Cookie 重複除去を実装。
8. **README カバレッジ表の自動生成・HTML 一本化・PSL のビルド時生成 (DOC-03〜07, DOC-10〜12 / T13)**:
   - `npm run spec:generate` による README カバレッジ表・PSL ルール定義（`src/security/psl-rules.generated.ts`）の自動生成、および `src/` 配下の古い HTML コピー廃止によるルート `popup.html` / `dashboard.html` への一本化を完了。

#### ③ v1.7.1 で解消した制限・機能強化
1. **要確認件数・重大度内訳・ステータス表示の一元整合と診断項目名の統一 (T01, T02, T11)**:
   - `src/shared/security-status.ts` に判定ルールを一元化し、「要確認（`requiresAttentionCount`）」と重大度内訳（`CRITICAL`〜`LOW` の合計）を常時一致させ、`INFO` 行を `pass`＋`info` 件数に統一。`info` 項目が `WARN` と表示される不整合や `Referrer-Policy` 未設定の過剰警告を解消。
   - Markdown の推奨対応ロードマップを固定文から要確認指摘ベースの動的生成へ刷新し、コードスパン（バックスラッシュ不使用）と表セル（`|` のみエスケープ）の処理を分離。さらに全固定診断項目で `status` 間の項目名揺れを廃止し、旧名称で保存された許容設定の後方互換性も維持。
2. **外部通信先の再定義（Resource Timing 主体）と調査完全性・混在コンテンツ表示の改善 (T05, T06)**:
   - `performance.getEntriesByType('resource')` による実際の読み込みリソースと、`document.baseURI` 基準で絶対 URL 解決した読み込み要素・メイン文書から通信先を集計するように刷新し、`link[rel="alternate"]`（`hreflang`）や `canonical`、`form[action]` 等の非通信参照を除外。
   - 混在コンテンツの観測値に対象要素とマスク済み URL を表示し、Content Script 収集の一部失敗時や通信先 0 件の矛盾時に完全性を `partial` として理由を記録するよう改善。
3. **Cookie の 6 用途分類と一般 Cookie チェックの独立化 (T07)**:
   - `advertising`（広告）と `consent`（同意管理）を加えた 6 用途分類へ拡張し、Application Insights（`ai_session` / `ai_user`）や ASP.NET CSRF（`__RequestVerificationToken`）等の名前対応表をパターン判定より優先。認証系指摘の有無に依存せず `SEC-COOKIE-SECURE-GENERAL` を独立出力し、HTTP ページでの PASS 観測値も「HTTP のため Secure は評価対象外」と明確化。
4. **CSP の重大度上限（最大 MEDIUM）・ヘッダー＋meta 積集合評価・ポリシー別問題点表 (T10)**:
   - 多層防御の原則に基づき CSP 指摘の最大重大度を `medium`（`MEDIUM`）に統一（CSP ありのページが CSP なしより重くならない設計）。HTTP ヘッダーと `<meta>` の全強制ポリシーを能力単位の積集合で評価し、観測値での問題点要約・Markdown でのポリシー別問題点テーブル出力・XFO と `frame-ancestors` の優先関係注記に対応。
5. **技術検出精度の向上・根拠整理・ASP.NET / WordPress / KEV 表示の改善 (T06, T08, T09, T11)**:
   - `distroHint` の適用対象を `Server` / `X-Powered-By` の版直後接尾辞に限定。Tomcat（＋Java 連動）、Classic ASP、Azure Application Gateway、Application Insights、Google Tag Manager（`gtag/js`）、Facebook SDK の検出を追加し、廃止済み GA タグ（`ga.js` / `analytics.js`）を `INFO` 通知化。
   - ASP.NET の `X-AspNet-Version`（露出指摘 `SEC-DISC-03` 追加）を CLR 版として表示し、CLR 2.0（`2.0.50727`）はサポート中の .NET Framework 3.5 SP1（2029-01-09 まで）と共通のため断定せず `Unknown` としてサポート期限を併記。Bootstrap 6 クラスと Tailwind CSS の誤認防止、WordPress コア `ver` 抽出とプラグイン/テーマ一覧表示、根拠の重複統合と代表 3 件表示、AngularJS 等の解消/未修正件数分離推奨文、CISA KEV 該当 CVE ID の名指し表示、HSTS `preload` 条件検証、証明書検証対象外の明記を完了。

#### ④ 残る既知の制限と将来の課題 (v1.8.0 以降の検討項目)
1. **パス部分に埋め込まれた機密情報**:
   - 保持・出力する URL からクエリパラメータおよびフラグメント（`?token=...#hash`）は確実に除去されますが、URL パスセグメント内に埋め込まれた値（例: `/reset-password/<token>` 等）は自動判別できないため除去されません。
2. **WordPress プラグイン・テーマの脆弱性 DB 照合**:
   - v1.7.1 では受動観測された `wp-content/plugins/<名前>/` および `wp-content/themes/<名前>/` の名前と `ver` パラメータの一覧表示のみを行い、オフライン脆弱性 DB との自動照合は対象外としています（プラグインエコシステムの収録規模・誤照合防止を含め v1.8 以降で検討）。
3. **ディストリ版バックポート判定の第2段階**:
   - 現在の第1段階（`distroHint` による `Needs Review` 扱い）から、ディストリビューション別のセキュリティ修正情報（OVAL / OSV Ubuntu・Debian エコシステム等）を参照・判定する第2段階への拡張は今後の検討課題です。
4. **Laravel CVE-2021-3129 の Ignition 連動マッピング制約**:
   - §2.4 に記載のとおり、デバッグページライブラリ `facade/ignition` の脆弱性を本体バージョン `< 8.4.3` にマッピングしているため、Ignition デバッグページの直接検出等への精緻化は今後の検討課題とします。

---


## 3. Chrome Web Store 申請・リリースフロー

> **リリース記録 (v1.6.5)**:
> `release/web-inspector-v1.6.5.zip` はタグ `v1.6.5`（コミット `c825dc9`）から作成されました。以後の main の差分は、ビルド入力(src/、public/、package.json、ロックファイル、ビルド設定、scripts/package.mjs)を含まず、公開用 zip の内容には影響しません。

### 3.1 手動でのパッケージ確認・ストア提出手順

1. **パッケージの確認**:
   - `release/web-inspector-vX.X.X.zip` のサイズ（約70〜100KB）および中身を確認します。
2. **ローカル実機検証**:
   - Chromeの `chrome://extensions/` を開き、「パッケージ化されていない拡張機能を読み込む」で `dist/` フォルダを読み込みます。
   - ポップアップのバージョンバッジおよび脆弱性DB更新日が正しく表示されることを確認します。
3. **ストア提出**:
   - [Chrome デベロッパー ダッシュボード](https://chrome.google.com/webstore/devconsole/) にログインします。
   - 対象アイテムを選択し、「パッケージのアップロード」から生成されたZIPファイルをアップロードします。
   - 変更点サマリーを入力し、「審査に送信」をクリックします。

---

### 3.2 脆弱性 DB 更新の自動マージと自動公開（D4 全自動パイプライン）

v1.7.0 以降では、**「脆弱性 DB だけの更新（第 4 要素リビジョン版: 例 `1.7.0.1`）」** と **「コード変更を含む更新（3 要素バージョン: 例 `1.7.1`）」** を機械的に分離し、DB だけの軽微な更新（`minor`）は週次ジョブから Chrome Web Store の審査提出・公開まで人の操作なしで完結する構成を備えています。一方、コード変更を含むリリースや重大な DB 変更（`major`）は、従来どおり人間のレビュー・承認（`STAGED_PUBLISH`）を経て公開されます。

```mermaid
flowchart TD
    subgraph WeeklyJob ["1. 週次 DB 更新 (advisory-db-update.yml)"]
        Cron["毎週月曜 05:23 JST 起動"] --> FetchBuild["上流取得・DB生成・差分分類<br>(diff-db.mjs / bump-db-revision.mjs)"]
        FetchBuild --> TestStep["検証・単体テスト・ビルド<br>(validate / verify-nvd / npm test)"]
        TestStep --> PlanStep["PR計画・ラベル判定<br>(pr-plan.mjs)"]
        PlanStep -->|minor & テスト合格 &<br>Appトークンあり &<br>ADVISORY_AUTO_MERGE=true| AutoMerge["GitHub App トークンで PR 作成<br>& gh pr merge --auto --squash"]
        PlanStep -->|major または テスト失敗<br>(db:tests-failing)| ManualReview["PR 作成・人間がレビュー<br>(自動マージしない)"]
    end

    subgraph ReleaseJob ["2. リリース判定・ストア提出 (release.yml)"]
        AutoMerge -->|main へマージ<br>(manifest.json 更新)| Prepare["リリース種別判定<br>(classify-release.mjs)"]
        ManualReview -->|人間がマージ| Prepare
        Prepare -->|4要素版 & DB関連ファイルのみ変更<br>& CWS_AUTO_PUBLISH=true| AutoRoute["Environment: chrome-web-store-auto<br>(承認なし / DEFAULT_PUBLISH)"]
        Prepare -->|コード変更を含む版 または 3要素版<br>または CWS_AUTO_PUBLISH!=true| ManualRoute["Environment: chrome-web-store<br>(レビュアー承認必須 / STAGED_PUBLISH)"]
        AutoRoute --> CwsReview["Chrome Web Store 審査通過後<br>ストアへ自動公開"]
        ManualRoute --> CwsStaged["Chrome Web Store 審査通過後<br>ダッシュボードで人間が公開"]
    end

    subgraph MonitorJob ["3. 審査ステータス監視 (cws-status.yml)"]
        CwsReview -.-> DailyCheck["毎日 1 回 status 監視<br>(cws-status.mjs)"]
        DailyCheck -->|REJECTED / SUSPENDED 等| AlertIssue["GitHub Issue 自動起票・通知<br>(ラベル: cws-status)"]
    end
```

#### ① 自動マージ (`advisory-db-update.yml` / `pr-plan.mjs` / `diff-db.mjs`) の安全条件
週次 PR が自動マージされるのは、以下の**すべて**を満たす場合に限られます：
1. `diff-db.mjs` の分類が **`minor`** であること。以下のいずれかに該当する場合はすべて **`major`** となり、自動マージされません：
   - 手動管理（`curated`）アドバイザリの削除、または製品全体の削除
   - EOL ステータスの逆行（`EOL` $\rightarrow$ `Supported` / `Maintenance`）
   - 上流ソースの取得失敗を含む場合（`syncStatus !== 'ok'`）
   - DB ファイルサイズが 50% を超えて増減した場合（初回 NVD 取り込み等を含む）
   - `schemaVersion` または `minExtensionVersion` が変更された場合
   - 既存アドバイザリの範囲（`range`）またはスコア（`cvssScore`）の変更が **20 件を超える**場合
   - CISA KEV フラグが解除（`true` $\rightarrow$ `false`）された場合
2. `npm test` および `npm run build` がすべて合格し、`db:tests-failing` ラベルが付いていないこと。
3. GitHub App トークン（`BOT_APP_CLIENT_ID` / `BOT_APP_PRIVATE_KEY`）が設定されていること（未設定時は警告を出して自動マージをスキップ）。
4. リポジトリ変数 `ADVISORY_AUTO_MERGE` が `'true'` であること。

#### ② 自動公開 (`release.yml` / `classify-release.mjs`) の安全条件
`main` ブランチへのマージ後、承認なし Environment（`chrome-web-store-auto`）および `DEFAULT_PUBLISH`（審査通過後の自動公開）が選ばれるのは、以下の**すべて**を満たす場合に限られます：
1. `public/manifest.json` の `version` が **4 要素**（例: `1.7.0.1`）であること。
2. 直前のリリースタグ（`v*`）からの変更ファイルが、`data/advisories/**`、`src/detection/advisory-db.json`、`public/manifest.json` のみに収まっていること。
3. `public/manifest.json` の変更行が `"version"` フィールドのみであること。
4. リポジトリ変数 `CWS_AUTO_PUBLISH` が `'true'` であること。

※ 上記を 1 つでも満たさない場合は、自動的に承認必須の Environment `chrome-web-store` と `STAGED_PUBLISH` にフォールバックします（手動実行 `workflow_dispatch` の際は `CWS_PUBLISH_TYPE` または実行時入力 `publish_type` を選択可能です）。

---

### 3.3 全自動パイプラインの停止方法（緊急停止手順）

上流データの異常や Chrome Web Store 審査での問題が発生し、自動マージ・自動公開を止めたい場合は、GitHub リポジトリの **Settings > Secrets and variables > Actions > Variables** で以下の **2 つの変数を `false` に変更**してください（コードの変更やコミットは不要で、即座に反映されます）。

| 変数名 | 停止時の設定値 | 効果 |
|---|---|---|
| **`ADVISORY_AUTO_MERGE`** | `false` | 週次 DB 更新 PR の自動マージを停止します（PR の作成とテストは継続され、人間が確認してマージします）。 |
| **`CWS_AUTO_PUBLISH`** | `false` | DB 限定リリースであっても自動公開（`chrome-web-store-auto` / `DEFAULT_PUBLISH`）を使わず、すべて承認必須の `chrome-web-store` / `STAGED_PUBLISH` に切り替えます。 |

---

### 3.4 誤った DB が公開されたときの戻し方（ロールバック手順）

万が一、誤った脆弱性範囲や不適切なエントリを含む DB リビジョン版（例: `1.7.0.2`）が Chrome Web Store に公開された場合は、Chrome Web Store の仕様上「過去のバージョン番号を再アップロード」することはできないため、**該当 PR を revert した上で、第 4 要素を 1 つ進めた新しいリビジョン版（例: `1.7.0.3`）を作成して公開**します。

```mermaid
sequenceDiagram
    autonumber
    actor Maintainer as メンテナー
    participant GitHub as GitHub (main)
    participant Actions as Release Workflow
    participant CWS as Chrome Web Store

    Maintainer->>GitHub: 1. 変数 ADVISORY_AUTO_MERGE と CWS_AUTO_PUBLISH を一旦 false に設定 (任意)
    Maintainer->>GitHub: 2. 問題の DB 更新 PR を Revert するブランチを作成
    Maintainer->>GitHub: 3. curated.json (excluded 等) を調整し build-db.mjs で正しい DB を再生成
    Maintainer->>GitHub: 4. bump-db-revision.mjs で manifest.json の第4要素を +1 (例: 1.7.0.2 → 1.7.0.3)
    Maintainer->>GitHub: 5. PR を作成し CI 合格を確認して main へマージ
    GitHub->>Actions: 6. Release ワークフロー起動 (v1.7.0.3 パッケージ生成)
    Actions->>CWS: 7. v1.7.0.3 をアップロード・審査提出・公開
```

1. **該当コミットの取り消しと除外設定**:
   - 問題となった DB 更新 PR を GitHub 上（または `git revert`）で取り消します。
   - 特定の上流 CVE/GHSA が原因の場合は、`data/advisories/curated.json` の `excluded` に該当 ID と除外理由を追加し、`npm run advisories:build` と `npm run advisories:validate` を実行します。
2. **新しい第 4 要素リビジョン番号の採番**:
   - 既にタグ付け・提出されたバージョン番号（例: `1.7.0.2`）よりも大きいバージョンにするため、`node scripts/advisories/bump-db-revision.mjs` を実行（または手動で編集）して、`public/manifest.json` の `version` を次の第 4 要素リビジョン（例: `1.7.0.3`）に進めます。
3. **マージと再リリース**:
   - `npm test` の合格を確認して `main` ブランチへマージすると、`Release` ワークフローが `v1.7.0.3` をビルドして Chrome Web Store へ提出します。

---

### 3.5 自動化を有効にするための初期設定（管理者向けチェックリスト）

全自動パイプラインを稼働させるには、リポジトリ管理者が GitHub および Google Cloud コンソールで以下の設定を行います。

1. **PR 作成・自動マージ用 GitHub App の作成と Secrets 登録**:
   - 標準の `GITHUB_TOKEN` で作成・マージされた PR は、無限ループ防止仕様により後続の `CI` や `Release` ワークフローを起動しません。そのため、リポジトリ専用の GitHub App（Permissions: `Contents: Read and write`, `Pull requests: Read and write`, `Issues: Read and write`）を作成してインストールし、Client ID を Variable `BOT_APP_CLIENT_ID`、秘密鍵を Secret `BOT_APP_PRIVATE_KEY` に登録します。
2. **`main` ブランチ保護ルール（Ruleset）の設定**:
   - リポジトリ設定で「Allow auto-merge（自動マージを許可）」を有効にします。
   - `main` の Ruleset で「Require status checks to pass（必須チェック: `CI`）」を設定し、「Require approval of the most recent reviewable push」はオフにするか、上記 GitHub App をバイパス対象に設定します。
3. **GitHub Environment `chrome-web-store-auto` と GCP Workload Identity Federation の設定**:
   - GitHub に Environment `chrome-web-store-auto` を「Required reviewers なし」「Deployment branches: `main` のみ」で作成します（既存の `chrome-web-store` は Required reviewers ありのまま維持します）。
   - Google Cloud の Workload Identity Pool Provider において、`repo:<owner>/<repo>:environment:chrome-web-store-auto` からの OIDC トークンを許可し、なりすまし防止のため `repository_id` および `repository_owner_id` の数値クレーム条件（immutable ID）を付与します。
4. **段階的な有効化（2 週間の試行期間）**:
   - 最初の 2 週間は `ADVISORY_AUTO_MERGE=false`・`CWS_AUTO_PUBLISH=false` のまま週次ジョブを動かし、生成される PR の差分とテスト結果を確認します。問題がなければ `ADVISORY_AUTO_MERGE=true` $\rightarrow$ `CWS_AUTO_PUBLISH=true` の順に有効化します。

---

## 4. 診断レポートの一括取得と整合性チェッカーの運用

リリース前の品質検証および回帰テストでは、レポート整合性チェッカー（[`scripts/report-lint.mjs`](../scripts/report-lint.mjs)）と診断レポート一括取得スクリプト（[`scripts/collect-reports.mjs`](../scripts/collect-reports.mjs)）を組み合わせて、件数集計・ステータス表示・ロードマップ・通信先・CSP 重大度などの不整合を機械的に検出します。

```mermaid
flowchart LR
    subgraph Offline ["1. 回帰検証・CI (オフライン完結)"]
        Fixtures["tests/fixtures/reports/<br>(合成フィクスチャ *.example.test)"] --> LintCmd["npm run reports:lint<br>(scripts/report-lint.mjs)"]
        LintCmd --> LintRes["全 9 検査項目 (R01〜R09) の合否判定"]
    end

    subgraph LiveCheck ["2. リリース前の実機・公開サイト検証 (ローカル実行)"]
        Build["npm run build<br>(dist/ 生成)"] --> Collect["npm run reports:collect<br>(scripts/collect-reports.mjs)"]
        Sites["サイト一覧<br>・scripts/report-sites.example.txt<br>・report-sites.local.txt (非追跡)"] --> Collect
        Collect --> Output["reports/<日時>/ (Git 非追跡)<br>・JSON / Markdown レポート<br>・_summary.md (チェッカー結果付き)<br>・snapshots/ (--snapshot 指定時)"]
    end
```

### 4.1 レポート整合性チェッカー (`scripts/report-lint.mjs` / `npm run reports:lint`)

診断レポートの JSON と Markdown のペアを入力として受け取り、内部データと出力文面の整合性を機械的に検査します。

#### 実行コマンド
```bash
# 既定: 回帰用合成フィクスチャ (tests/fixtures/reports/) の全件を検査
npm run reports:lint

# 任意の出力フォルダまたは特定の JSON レポートを指定して検査
node scripts/report-lint.mjs reports/2026-11-08_0900
node scripts/report-lint.mjs path/to/web-inspector-report-example.test-2026-11-08.json
```

#### 検査項目一覧（R01〜R09）
| ID | 検査内容 |
|---|---|
| **R01** | サマリーの「要確認」件数（`requiresAttentionCount`）と重大度内訳（`CRITICAL`〜`LOW` の合計）が一致し、`INFO` 件数が `pass`＋`info` と一致すること |
| **R02** | Markdown セクション 5 の表のステータス表記（`PASS` / `INFO` / `WARN` / `FAIL`）が JSON の `status` と一致すること |
| **R03** | 推奨対応ロードマップ（セクション 13）の各行に対応する要確認の指摘が存在し、固定文や不要な行が出ないこと |
| **R04** | 検出根拠の URL ホストが通信先（セクション 9）に含まれ、`alternate` リンクや `form[action]` の送信先だけの非通信ホストが混入していないこと |
| **R05** | 固定診断項目（`X-Frame-Options`, `HSTS`, `XCTO`, `Referrer-Policy`, `Permissions-Policy`, `HTTPS暗号化通信`, `CORS` 等）の項目名が `status` によって変化しないこと |
| **R06** | Markdown のコードスパン（`` `...` ``）内に不要なバックスラッシュエスケープ（`\_`, `\[` 等）が含まれないこと |
| **R07** | 同一技術内で同じ種別・同じ値の検出根拠が重複して出力されていないこと |
| **R08** | 調査完全性が「完全（`complete`）」である場合、外部通信先（自ホストを含む読み込み元）が 1 件以上計上されていること |
| **R09** | CSP が設定されているページの CSP 指摘重大度が、CSP 未設定（`MEDIUM`）を上回らないこと（`HIGH` / `CRITICAL` が出ないこと） |

---

### 4.2 診断レポート一括取得スクリプト (`scripts/collect-reports.mjs` / `npm run reports:collect`)

`dist/` にビルドされた拡張機能を読み込んだ Chromium（Playwright）を起動し、指定された URL 一覧を 1 サイトずつ順番に受動閲覧して JSON と Markdown の両レポートを保存します。取得完了後には自動で `report-lint.mjs` が実行され、サイトごとの合否一覧が `<出力先>/_summary.md` に記録されます。

#### 実行コマンドと主なオプション
```bash
# 1. 事前に最新の拡張機能をビルドする
npm run build

# 2. 公開テストサイト・各技術公式サイトの一覧で一括取得する（応答の遅いサイト向けに --timeout を延長）
npm run reports:collect -- --sites scripts/report-sites.example.txt --timeout 90000

# 3. ローカルの検証リスト (report-sites.local.txt があれば優先使用) で取得する
npm run reports:collect

# 4. 単一 URL を直接指定して取得する
node scripts/collect-reports.mjs https://example.com/

# 5. 回帰調査用スナップショット (HTML・サニタイズ済みヘッダー・Resource Timing・値除外済みCookie属性) も保存する
npm run reports:collect -- --sites scripts/report-sites.example.txt --snapshot --timeout 90000
```

- `--sites <file>`: 1 行 1 URL のサイト一覧ファイルを指定します（`#` 以降はコメント。未指定時は `report-sites.local.txt` が存在すればそれを使用し、無ければ [`scripts/report-sites.example.txt`](../scripts/report-sites.example.txt) を使用します）。
- `--out <dir>`: 出力先ディレクトリを指定します（既定: `reports/<YYYY-MM-DD_HHmm>`）。
- `--snapshot`: `<出力先>/snapshots/` に HTML、機密値（`Set-Cookie` の値や `Authorization` / `Cookie` ヘッダー）を除去したメイン文書レスポンスヘッダー、Resource Timing 一覧、および値を除去した Cookie 属性一覧を保存します。
- `--wait <ms>` / `--timeout <ms>`: ページ読み込み完了後の待機時間（既定 `2000` ms）および読み込みタイムアウト上限（既定 `30000` ms）を指定します。
- `--strict-tls`: TLS 証明書エラーのあるサイトを取得対象から除外します（既定では検証目的のため警告を記録したうえで取得します）。

---

### 4.3 実サイトのレポート・ホスト名の取り扱いに関する厳守事項

> [!CAUTION]
> **実サイトの診断レポートを公開リポジトリに載せないでください。**  
> 第三者が運営する実サイトのレポートには、当該サイトの構成情報やセキュリティ設定上の指摘事項が含まれます。これらを公開リポジトリへコミット・プッシュしたり、公開 Issue / Pull Request に貼り付けたりすることは厳禁です。

1. **出力先とローカルリストの Git 非追跡維持**:
   - 一括取得スクリプトの既定出力先である `reports/` ディレクトリおよびローカル用の URL 一覧 `report-sites.local.txt` は `.gitignore` に登録されています。これらをリポジトリ内の別ディレクトリへコピーしたり、`git add -f` で強制追加したりしないでください。
2. **回帰用フィクスチャ・テスト・作業記録におけるホスト名規則**:
   - リポジトリにコミットする回帰用レポートフィクスチャ（`tests/fixtures/reports/`）、単体テスト、コード内コメント、および作業記録（WORKLOG・完了報告書）には、**公開されていない実サイトのホスト名を記載しないでください**。
   - 公開テストサイト（`vulnweb.com`, `testfire.net`, `badssl.com` 等）および各技術の公式サイト（`wordpress.org`, `react.dev`, `getbootstrap.com` 等）以外の再現ケースを作成する場合は、必ずホスト名を **`*.example.test` に置き換えた合成データ**を使用してください。
3. **公開サイトのスナップショット保存時の注意**:
   - `tests/fixtures/snapshots/` に回帰テスト用のスナップショットを配置する場合は、上記の公開テストサイト・公式サイトのみを対象とし、Cookie の値（Value）や認証ヘッダーが含まれていないことを必ず確認してください（`--snapshot` は既定で値をマスク・除外します）。

---

## 5. テストコードの規約とCI品質検証 (v1.8.0)

### 5.1 テストコードの作成規約（Test Hygiene）

テストの保守性と安全性を担保するため、以下のルールを遵守します（[`tests/test-hygiene.test.ts`](../tests/test-hygiene.test.ts) により機械的に検査されます）。

1. **バージョン番号・件数・日付・dataVersion を直接書かない**:
   - バージョン番号の期待値は、テストコード内に直接ハードコードせず、`tests/helpers/release-version.ts` の `readPackageVersion()` を用いて `package.json` から動的に取得します（`public/manifest.json` との比較には `isSameRelease` を使用）。
   - 総テスト件数や日付、脆弱性 DB のバージョン等の変動する値をテストの期待値に固定してはなりません。
2. **脆弱性照合テストにおける固定 DB の使用**:
   - 脆弱性照合（Advisory）機能のテストには、固定の検証用 DB である [`tests/fixtures/advisory-db.fixture.json`](../tests/fixtures/advisory-db.fixture.json) を使用します。
   - 同梱の本番 DB（`src/detection/advisory-db.json`）をテスト内で直接読み込んではなりません（同梱 DB の参照が許可されているのは、スキーマ検証などの許可リストに限定されたテストのみです）。

### 5.2 脆弱性 DB 自動リリースの予行 (`scripts/ci/rehearse-db-release.mjs`)

脆弱性 DB の自動更新パイプラインおよび週次自動リリース（例: `v1.8.0.1` などの 4 桁パッチリリース）が正常に機能するかを事前に検証するため、予行スクリプトが用意されています。

```bash
node scripts/ci/rehearse-db-release.mjs
```

- **スクリプトの動作**: 元の作業ツリーは変更せず、一時コピーを作成して `public/manifest.json` の 4 つ目の数字（DB の版）を採番し、`dataVersion` を進めて integrity を計算し直したうえで、テストを実行します。
- **CI での実行**: GitHub Actions の `ci.yml` ワークフロー内の `db-release-rehearsal` ジョブで自動実行され、プッシュおよび Pull Request ごとに DB 単独リリースの検証フローが破壊されていないかを検査します。

### 5.3 パッケージおよびデータベースのサイズ上限検査 (`scripts/ci/check-size.mjs`) (G7)

拡張機能の配布パッケージサイズおよび同梱されるオフライン脆弱性データベースの肥大化を防ぐため、サイズ上限検査スクリプトが CI で自動実行されます。

```bash
node scripts/ci/check-size.mjs
```

- **内蔵脆弱性データベース (`src/detection/advisory-db.json`)**: 上限 **2 MB**（2 MiB）
- **ビルド成果物合計 (`dist/` ディレクトリ全体)**: 上限 **3 MB**（3 MiB）
- **早期警告**: 各上限の 80% を超過した場合、警告（WARN）が出力されます。


