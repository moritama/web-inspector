# Web Technology & Security Inspector - 開発・変更計画書 (Version 1.0 〜 1.6.0)

本書は、Chrome / Edge (Manifest V3) 対応ブラウザ拡張機能『Web Technology & Security Inspector』の初期開発から最新バージョン（v1.6.0）に至るまでの全体ロードマップ、システムアーキテクチャ、およびフェーズ別開発計画を体系化した統括計画書です。

各フェーズの詳細な開発計画・設計仕様については、[`docs/phases/`](./phases/) 配下の個別ドキュメントに記載しています。

---

## 1. ロードマップ変遷概要

```mermaid
timeline
    title Web Technology & Security Inspector 開発ロードマップ (v1.0 〜 v1.6)
    section v1.0.0 (Phase 1)
        初期MVPリリース : Manifest V3基盤整備 : 主要Webサーバー/言語/CMS/JS検出 : 基本HTTPヘッダー/Cookie/HTTPS診断
    section v1.1.0 (Phase 2)
        ライブラリセキュリティ : CSSアセット解析 (ADD-02) : CSS/JSバージョン整合性 (ADD-03) : オフライン脆弱性/EOL照合 (ADD-04/05)
    section v1.2.0〜1.4.0 (Phase 3)
        診断精密化・ノイズ削減 : Cookie用途別リスク判定 (IMP-01) : CSP構文解析・フォールバック (IMP-02) : 調査完全性評価 (IMP-08)
    section v1.5.0 (Phase 4)
        運用支援・差分分析 : 履歴Diff原因推定 (IMP-09) : 誤検知除外管理 (IMP-10) : 通信先PSL分析 (IMP-11) : 包括Markdown (IMP-12) : 連動検知プロトタイプ (IMP-13)
    section v1.6.0 (Phase 5 & 6)
        カバレッジ拡大 & Implication Engine : バックエンドFW 10種 (IMP-14) : フロント・UI 12種 (IMP-15) : ホスティング/外部サービス 12種 (IMP-16) : 3層分離・稼働状態管理 (IMP-17) : 可視化・受動調査制限明記 (IMP-18/19)
```

---

## 2. フェーズ一覧と詳細計画へのリンク

各フェーズをクリックすると詳細な設計・受入基準・トレーサビリティ仕様書を確認できます。

| フェーズ | 対象バージョン | テーマ | 主な機能ID | 詳細ドキュメント |
|---|:---:|---|---|:---:|
| **Phase 1** | v1.0.0 | **初期MVP・基盤診断エンジン開発** | F01 〜 F12 | [詳細計画書 (Phase 1)](./phases/PHASE_1_INITIAL_FOUNDATION.md) |
| **Phase 2** | v1.1.0 | **ライブラリセキュリティ & オフラインCVE/EOL統合** | ADD-01 〜 ADD-08 | [詳細計画書 (Phase 2)](./phases/PHASE_2_LIBRARY_SECURITY.md) |
| **Phase 3** | v1.2.0 〜 1.4.0 | **診断エンジン精密化 & ノイズ（誤検知）削減** | IMP-01 〜 IMP-08 | [詳細計画書 (Phase 3)](./phases/PHASE_3_ENGINE_REFINEMENT.md) |
| **Phase 4** | v1.5.0 | **調査運用支援・差分分析・連動検知プロトタイプ** | IMP-09 〜 IMP-13 | [詳細計画書 (Phase 4)](./phases/PHASE_4_OPERATIONAL_SUPPORT.md) |
| **Phase 5** | v1.6.0 | **検出カバレッジの大幅拡大（主要技術網羅）** | IMP-14 〜 IMP-16 | [詳細計画書 (Phase 5)](./phases/PHASE_5_COVERAGE_EXPANSION.md) |
| **Phase 6** | v1.6.0 | **Implication Engine 高度化 & 可視化・レポート連携** | IMP-17 〜 IMP-19 | [詳細計画書 (Phase 6)](./phases/PHASE_6_IMPLICATION_ENGINE.md) |

### 関連運用ドキュメント
- [技術検出仕様・判定基準書 (`docs/DETECTION_SPECIFICATION.md`)](./DETECTION_SPECIFICATION.md) - 全対応技術の判定シグナル、正規表現、Implication推論マトリクス、バージョン抽出基準
- [保守・リリース運用ガイド (`docs/MAINTENANCE_GUIDE.md`)](./MAINTENANCE_GUIDE.md) - バージョンアップ手順、脆弱性DB更新手順、チェックリスト
- [Chrome Web Store 申請ガイド (`docs/CHROME_WEB_STORE_GUIDE.md`)](./CHROME_WEB_STORE_GUIDE.md) - 配布ZIPのストア提出手順と権限の正当化説明

---

## 3. システムアーキテクチャ構成 (v1.6.0)

```mermaid
graph TD
    subgraph Browser ["Webブラウザ (Chrome / Edge)"]
        subgraph ActiveTab ["閲覧中のWebページ"]
            PageDOM["DOM / HTML / Scripts / CSS"]
            MixedRes["混在コンテンツ (HTTPリソース)"]
        end

        subgraph Extension ["Web Inspector 拡張機能 (Manifest V3)"]
            CS["Content Script<br>(DOM/アセット/混在コンテンツ収集)"]
            SW["Service Worker (バックグラウンド)<br>(HTTPヘッダー収集 / Cookie取得 / 統括)"]
            
            subgraph Engine ["解析エンジン (v1.6.0)"]
                DE["Detection Engine<br>(ルール照合 / 確信度計算)"]
                IE["Implication Engine<br>(3層分離 / 稼働状態推定 / 循環防止)"]
                SE["Security Engine<br>(ヘッダー / Cookie / HTTPS / CSP評価)"]
            end

            subgraph StorageArea ["ローカルストレージ"]
                LocalStorage["chrome.storage.local<br>(調査履歴 / 誤検知除外設定)"]
                AdvisoryDB["内蔵オフライン脆弱性DB<br>(advisory-db.json)"]
            end

            subgraph UI ["ユーザーインターフェース"]
                Popup["Popup UI (ポップアップ画面)<br>・直接/連動/稼働状態バッジ<br>・サマリー & 詳細モーダル"]
                Dashboard["Dashboard UI (詳細ダッシュボード)<br>・履歴Diff原因分析<br>・サードパーティPSL分析<br>・Markdown/CSV/JSON出力"]
            end
        end
    end

    ActiveTab -->|DOM解析・監視| CS
    ActiveTab -->|HTTP通信 webRequest| SW
    CS -->|シグナル送信| SW
    SW --> DE
    DE --> IE
    IE --> SE
    SE --> AdvisoryDB
    SW --> LocalStorage
    SW <-->|状態取得・操作| Popup
    LocalStorage <--> Dashboard
```

---

## 4. 診断・分析シーケンス (v1.6.0)

```mermaid
sequenceDiagram
    autonumber
    actor User as ユーザー
    participant Tab as 対象Webページ
    participant SW as Service Worker
    participant CS as Content Script
    participant DE as Detection Engine
    participant IE as Implication Engine
    participant SE as Security Engine
    participant UI as Popup / Dashboard

    Note over Tab,SW: ページアクセス時
    Tab->>SW: HTTPレスポンス発生 (onHeadersReceived)
    SW->>SW: レスポンスヘッダー・Cookie情報の一時キャッシュ

    User->>UI: 拡張機能アイコンをクリック / 調査要求
    UI->>SW: 調査リクエスト送信 (tabId, url)
    SW->>CS: DOM情報解析リクエスト
    CS->>Tab: meta, script, link, HTML特徴, 混在コンテンツ収集
    CS-->>SW: DOM解析結果返却
    SW->>SW: chrome.cookies.getAll (属性のみ取得・値は除外)
    
    SW->>DE: 観測シグナル入力 (DOM, Headers, Cookies)
    DE->>DE: ルール照合 (Direct固有シグナル / Associated候補集約)
    DE->>IE: 検出結果リスト (確信度 ≥ 50%)
    
    loop 連動推論 (最大2パス & 循環防止)
        IE->>IE: 依存関係解決 (framework-dependency, runtime-dependency, possible-runtime)
        IE->>IE: ランタイム状態判定 (confirmed / possible / unknown / not-applicable)
    end
    
    IE->>SE: 技術リスト & セキュリティ診断実行
    SE->>SE: HSTS, CSP, Cookie用途別, 混在コンテンツ, オフラインCVE照合
    SE-->>SW: 統合診断レポート (InspectionReport)
    SW->>SW: 履歴保存 (chrome.storage.local)
    SW-->>UI: 診断結果返却
    UI->>User: 直接/連動/候補バッジ、推論経路、受動的調査制限を明記して表示
```

---

## 5. 全機能トレーサビリティ・マトリクス

| 機能ID | 機能名 | 実装バージョン | 実装ファイル | 単体テスト | フェーズ |
|---|---|:---:|---|---|:---:|
| **F01** | Webサーバー検出 | v1.0.0 | `rules/server.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F02** | 言語・ランタイム検出 | v1.0.0 / v1.5.0 | `rules/language.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F03** | CMS検出 | v1.0.0 | `rules/cms.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F04** | JSフレームワーク検出 | v1.0.0 / v1.6.0 | `rules/frontend.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F05** | JS/CSSライブラリ検出 | v1.0.0 / v1.6.0 | `rules/frontend.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F06** | CDN / WAF推定 | v1.0.0 | `rules/cdn-waf.json`, `engine.ts` | `detection.test.ts` | Phase 1 |
| **F07** | セキュリティヘッダー診断 | v1.0.0 | `src/security/headers.ts` | `security.test.ts` | Phase 1 |
| **F08** | Cookie属性診断 | v1.0.0 / v1.3.0 | `src/security/cookies.ts` | `cookies.test.ts` | Phase 1 |
| **F09** | HTTPS・混在コンテンツ診断 | v1.0.0 | `src/security/https.ts` | `security.test.ts` | Phase 1 |
| **F10** | 判定根拠・確信度計算 | v1.0.0 | `src/detection/confidence.ts` | `detection.test.ts` | Phase 1 |
| **F11** | JSON / CSVエクスポート | v1.0.0 / v1.6.0 | `src/export/json.ts`, `csv.ts` | `export.test.ts` | Phase 1 |
| **F12** | 調査履歴保存・管理 | v1.0.0 | `src/storage/history.ts` | `diff.test.ts` | Phase 1 |
| **ADD-01〜03** | CSSアセット・整合性照合 | v1.1.0 | `content-script.ts`, `version-integrity.ts` | `version-check.test.ts` | Phase 2 |
| **ADD-04〜08** | オフラインCVE/EOL・セキュリティビュー | v1.1.0 | `advisory/matcher.ts`, `dashboard.ts` | `advisory.test.ts` | Phase 2 |
| **IMP-01** | Cookie用途別動的判定 | v1.2.0 | `security/cookies.ts` | `cookies.test.ts` | Phase 3 |
| **IMP-02/05** | CSPディレクティブ構文解析 | v1.2.0 / v1.3.0 | `security/csp-parser.ts` | `csp-parser.test.ts` | Phase 3 |
| **IMP-03/06/07** | 脆弱性DB鮮度・パッケージ除外 | v1.3.0 | `advisory/matcher.ts` | `advisory.test.ts` | Phase 3 |
| **IMP-04** | プレフィックス整合性・CHIPS | v1.3.0 | `security/cookies.ts` | `cookies.test.ts` | Phase 3 |
| **IMP-08** | 調査完全性・エビデンス品質 | v1.3.0 | `shared/coverage.ts` | `coverage.test.ts` | Phase 3 |
| **IMP-09** | 履歴Diff原因自動推定 | v1.5.0 | `storage/diff.ts` | `diff.test.ts` | Phase 4 |
| **IMP-10** | 誤検知・許容除外管理 (FindingId) | v1.5.0 | `storage/exceptions.ts`, `identity.ts` | `exceptions.test.ts` | Phase 4 |
| **IMP-11** | 外部通信先PSLサードパーティ分析 | v1.5.0 | `network/domain-analyzer.ts` | `domain-analyzer.test.ts` | Phase 4 |
| **IMP-12** | 15セクション包括Markdownレポート | v1.5.0 / v1.6.0 | `export/markdown.ts` | `markdown.test.ts` | Phase 4 |
| **IMP-13** | 連動検知プロトタイプ・候補集約 | v1.5.0 | `detection/engine.ts` | `detection.test.ts` | Phase 4 |
| **IMP-14** | バックエンドFW 10種検出 | **v1.6.0** | `rules/backend.json`, `engine.ts` | `detection.test.ts` | Phase 5 |
| **IMP-15** | フロント・UI 12種検出 | **v1.6.0** | `rules/frontend.json`, `engine.ts` | `detection.test.ts` | Phase 5 |
| **IMP-16** | ホスティング・外部サービス 12種検出 | **v1.6.0** | `rules/services.json`, `engine.ts` | `detection.test.ts` | Phase 5 |
| **IMP-17** | Implication Engine 高度化 (3層/状態) | **v1.6.0** | `detection/engine.ts`, `types.ts` | `detection.test.ts` | Phase 6 |
| **IMP-18** | 検出結果可視化 (バッジ/制限明記) | **v1.6.0** | `popup.ts`, `dashboard.ts`, CSS | - | Phase 6 |
| **IMP-19** | CVE/EOL誤報防止・レポート連携 | **v1.6.0** | `export/markdown.ts`, `csv.ts` | `markdown.test.ts`, `export.test.ts` | Phase 6 |
