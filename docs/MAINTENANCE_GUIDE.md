# Web Technology & Security Inspector - 保守・リリース運用ガイド

本書は、『Web Technology & Security Inspector』のバージョンアップ手順、内蔵オフライン脆弱性データベース（`advisory-db.json`）の更新手順、および配布用パッケージ作成・ストア申請フローをまとめた開発者・メンテナー向け運用ガイドです。

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
        SW["src/background/service-worker.ts<br>(EXTENSION_VERSION フォールバック)"]
        HTML["popup.html / dashboard.html<br>(JS実行前の初期HTMLテキスト)"]
        Docs["README.md / ドキュメント<br>(バッジ・見出しの表記)"]
    end

    Manifest --> AutoReflect
    Pkg --> AutoReflect
    MasterSources -.->|整合性維持| SyncNeeded
```

- **画面バッジの自動取得**: ポップアップ画面やダッシュボード画面のバージョンバッジ（`v1.6.0` 等）は、実行時に `chrome.runtime.getManifest().version` から動的に読み込まれます。
- **ZIPファイル名の自動連動**: `npm run package` 実行時、`scripts/package.mjs` が `package.json` の `version` を読み取り、自動的に `release/web-inspector-v{version}.zip` を出力します。

---

### 1.2 バージョン変更時の更新対象ファイル・チェックリスト

バージョン（例: `1.6.0` $\rightarrow$ `1.7.0`）を変更する際は、以下のファイルを更新します。

| No | ファイルパス | 役割・更新内容 | 必須区分 |
|:---:|---|---|:---:|
| 1 | [`public/manifest.json`](../public/manifest.json) | `"version": "X.X.X"`（Chrome Web Store認識用） | **【必須】** |
| 2 | [`package.json`](../package.json) | `"version": "X.X.X"`（ZIP出力スクリプト用） | **【必須】** |
| 3 | [`src/detection/rules/index.ts`](../src/detection/rules/index.ts) | `export const RULES_VERSION = 'X.X.X';`（レポート記録用） | **【必須】** |
| 4 | [`src/background/service-worker.ts`](../src/background/service-worker.ts) | `EXTENSION_VERSION` のフォールバック文字列 | 推奨 |
| 5 | [`src/popup/popup.ts`](../src/popup/popup.ts) | `setupVersionBadge()` のフォールバック文字列 | 推奨 |
| 6 | [`src/dashboard/dashboard.ts`](../src/dashboard/dashboard.ts) | `setupVersionBadge()` のフォールバック文字列 | 推奨 |
| 7 | [`src/popup/popup.html`](../src/popup/popup.html) / `popup.html` | `<span id="brandVersion">vX.X.X</span>` 初期HTMLテキスト | 推奨 |
| 8 | [`src/dashboard/dashboard.html`](../src/dashboard/dashboard.html) / `dashboard.html` | `<span id="dashboardVersion">vX.X.X</span>` 初期HTMLテキスト | 推奨 |
| 9 | [`README.md`](../README.md) | バッジ（`version-X.X.X-blue.svg`）および機能一覧見出し | 推奨 |

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
    Test-->>Dev: All Passed (125 tests)
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

### 2.3 脆弱性DBの更新手順（ステップ・バイ・ステップ）

#### ステップ 1: 最新アドバイザリの同期
ターミナルで以下のコマンドを実行します。
```bash
npm run advisories:sync
```
- 主要ライブラリ（jQuery, React, Vue, Bootstrap, PHP, WordPress, Laravel等）の最新CVEおよびEOL情報が取得され、`src/detection/advisory-db.json` が上書き更新されます。

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
| **CVE-2021-3129** | Laravel | `< 8.4.3` | `< 2.5.2` (Ignition) | 連動パッケージ置換 | NVD CVE-2021-3129 の configurations において、`cpe:2.3:a:facade:ignition < 2.5.2` (vulnerable: true) と `cpe:2.3:a:laravel:laravel < 8.4.2` (vulnerable: false) が連動ノードとして定義。Laravel 8.4.3 で ignition 2.5.2 以降に依存引き上げが行われたため、本体バージョン `< 8.4.3` としてマッピング。 | [NVD CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129) |
| **CVE-2022-25869** | AngularJS | `<= 1.8.3` | `(CPE未定義)` | GHSA 主導エントリ | NVDにCVSSスコア(6.1)は登録されているがCPE該当範囲情報が未定義のため、一次情報としてGitHub Advisory Database (GHSA-prc3-vjfx-vhm9: `<= 1.8.3`) を採用。EOLのため公式パッチなし (fixedVersion: null)。 | [GHSA-prc3-vjfx-vhm9](https://github.com/advisories/GHSA-prc3-vjfx-vhm9) |

---

### 2.5 公開中バージョン (v1.3.3) における過去の脆弱性DB誤記一覧

v1.6.4 への改訂に伴う NVD CPE 機械的突合により、公開中バージョン (v1.3.3) に存在していた以下の不正確なエントリが特定され、是正・除外されました。

1. **Vue.js CVE-2020-13426 の誤登録 (除外)**:
   - 1.3.3 では `CVE-2020-13426` が「ReDoS in vue template compiler (< 2.6.10)」として登録されていましたが、NVD の一次情報では WordPress のサードパーティプラグイン「Multi-Scheduler」の CSRF 脆弱性であることが判明しました。Vue.js 本体とは無関係のため除外しました（Vue 2 系は全件 EOL として保護）。
2. **WordPress CVE-2023-32243 の誤登録 (除外)**:
   - WordPress 本体ではなくサードパーティプラグイン「Essential Addons for Elementor」の脆弱性であったため除外。
3. **Node.js CVE-2022-35255 の誤登録 (除外)**:
   - HTTP Request Smuggling に関する不正確な記述であったため除外。
4. **React CVE-2018-6341 の範囲過不足 (是正)**:
   - 1.3.3 の `< 16.0.0` から、NVD CPE 通りの 16 系 SSR 5 ブランチ (`>= 16.0.0, < 16.0.1 || ...`) に是正。
5. **nginx CVE-2021-23017 の範囲過剰 (是正)**:
   - `< 1.21.0` から、修正版 1.20.1 を除外した `>= 0.6.18, < 1.20.1` に是正。
6. **Laravel CVE-2018-15133 の 1 系統化 (是正)**:
   - `< 5.6.30` から、5.5 系のパッチ版を考慮した `< 5.5.41 || >= 5.6.0, < 5.6.30` に是正。

---

---


## 3. Chrome Web Store 申請・リリースフロー

1. **パッケージの確認**:
   - `release/web-inspector-vX.X.X.zip` のサイズ（約70〜100KB）および中身を確認します。
2. **ローカル実機検証**:
   - Chromeの `chrome://extensions/` を開き、「パッケージ化されていない拡張機能を読み込む」で `dist/` フォルダを読み込みます。
   - ポップアップのバージョンバッジおよび脆弱性DB更新日が正しく表示されることを確認します。
3. **ストア提出**:
   - [Chrome デベロッパー ダッシュボード](https://chrome.google.com/webstore/devconsole/) にログインします。
   - 対象アイテムを選択し、「パッケージのアップロード」から生成されたZIPファイルをアップロードします。
   - 変更点サマリーを入力し、「審査に送信」をクリックします。
