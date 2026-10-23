# フェーズ3詳細開発計画書: 診断エンジン精密化 & ノイズ（誤検知）削減 (v1.2.0 〜 v1.4.0)

**フェーズ番号:** Phase 3  
**対応バージョン:** v1.2.0 〜 v1.4.0  
**主目的:** 実務運用に即した実効的なセキュリティスコアリング、誤検知（ノイズ）の劇的削減、および調査完全性の自己評価  
**対象機能ID:** IMP-01 〜 IMP-08  

---

## 1. フェーズ概要と目的

従来の画一的な静的診断ツールでは、「すべてのCookieにHttpOnlyが付いていないと警告」「CSPのフォールバック仕様を考慮せず誤認」など、Webサイトの正常な運用においてノイズとなる過剰警告が多数発生していました。  
本フェーズでは、Cookieの用途（認証、CSRF、解析タグ、UI設定）に応じた動的重大度判定、W3C仕様に完全準拠したCSPディレクティブパーサー、および調査時の観測制限を明示するCoverage評価を導入し、診断の信頼性を飛躍的に高めました。

```mermaid
flowchart TD
    subgraph CookieClassification ["Cookie用途別動的判定 (IMP-01)"]
        RawCookie["観測されたCookie"] --> Classify{"用途カテゴリ推定"}
        Classify -->|セッション / 認証トークン| AuthCookie["認証系: HttpOnly + Secure 必須<br>(欠如時: HIGH/MEDIUM)"]
        Classify -->|CSRFトークン (XSRF)| CsrfCookie["CSRF系: Secure必須<br>※JS読取前提のためHttpOnly欠如は許容"]
        Classify -->|アクセス解析・広告タグ| TrackingCookie["解析系: Secure推奨<br>※HttpOnly警告は抑制 (LOW/INFO)"]
        Classify -->|UI設定 (テーマ・言語等)| UiCookie["UI設定系: HttpOnly警告対象外"]
    end

    subgraph CspEvaluation ["CSP構文解析 & フォールバック (IMP-02)"]
        CspHeader["CSPヘッダー文字列"] --> CspParser["ディレクティブ構文解析"]
        CspParser --> FallbackCheck{"script-src が未定義?"}
        FallbackCheck -->|Yes| UseDefault["default-src をフォールバック継承"]
        FallbackCheck -->|No| UseScript["script-src を直接評価"]
        UseDefault --> KeywordEval["危険キーワード評価<br>('unsafe-inline', 'unsafe-eval', *)"]
        UseScript --> KeywordEval
    end
```

---

## 2. 実装機能一覧 (IMP-01 〜 IMP-08)

| 機能ID | 機能名 | 概要・仕様 |
|---|---|---|
| **IMP-01** | Cookie用途別動的リスク判定 | Cookie名やプレフィックスから用途（認証、CSRF、解析、UI）を自動分類。JavaScriptによる読み取りが必要な解析タグ・UI Cookieに対する不適切なHttpOnly警告を抑制し、ノイズを削減 |
| **IMP-02** | CSPディレクティブ構文解析 | CSP文字列をパースし、ディレクティブ構造を分解。`script-src` 未指定時に `default-src` がフォールバックされるW3C仕様に準拠した正当な危険度判定を実現 |
| **IMP-03** | オフライン脆弱性DB検証自動化 | ビルド時スクリプト `validate-advisories.mjs` を導入。スキーマ整合性、ファイルサイズ上限（2MB）、Semantic Versioning範囲の妥当性をCI/ビルド時に強制検証 |
| **IMP-04** | Cookieプレフィックス & CHIPS診断 | `__Host-`（Secure必須、Path=/必須、Domain属性禁止）および `__Secure-`（Secure必須）の仕様準拠診断。サードパーティCookie廃止対応の CHIPS (`Partitioned`) 属性の認識 |
| **IMP-05** | `<meta>` タグ経由のCSP解析 | HTTPレスポンスヘッダーだけでなく、HTML内の `<meta http-equiv="Content-Security-Policy">` で配信されたCSPディレクティブを統合収集・解析 |
| **IMP-06** | 脆弱性DB更新日・鮮度明示 | 脆弱性DBのメタデータ更新日（`YYYY-MM-DD`）をUIおよび出力レポートに常時表示。31日以上経過した古いDBに対しては鮮度警告を表示 |
| **IMP-07** | Linuxパッケージ版の脆弱性判定保留 | `Ubuntu`, `Debian`, `RedHat` などのディストリビューション固有ビルド（バックポート修正）を検知した場合、安易なバージョン単純比較によるCVE誤報を回避し「判定保留」として安全に処理 |
| **IMP-08** | 調査範囲・完全性 (Coverage) 評価 | キャッシュヒットや事前アクセス未観測によるシグナル欠落を検知し、Coverage スコア（0〜100）およびステータス（`complete`, `partial`）をレポートに記録 |

---

## 3. Cookie用途判定と重大度マトリクス (IMP-01)

| 用途カテゴリ | 代表的なCookie名パターン | Secure属性欠如時 | HttpOnly属性欠如時 | 判定根拠 |
|---|---|:---:|:---:|---|
| **セッション・認証** | `session`, `token`, `PHPSESSID`, `JSESSIONID`, `laravel_session`, `connect.sid` | **HIGH** | **HIGH** | 漏洩時にアカウント乗っ取りの直接的被害が生じるため厳格診断 |
| **CSRF保護** | `XSRF-TOKEN`, `csrf_token`, `csrftoken` | **MEDIUM** | **INFO (許容)** | SPA等でJavaScriptがヘッダーに再転送する設計が一般的であるため |
| **アクセス解析・タグ** | `_ga`, `_gid`, `_clck`, `_fbp` | **LOW** | **INFO (許容)** | クライアント側JSによる送受信を前提としているため |
| **UI設定・その他** | `theme`, `lang`, `sidebar_state` | **INFO** | **INFO (許容)** | 機密情報を含まない表示設定であるため |

---

## 4. 受入基準 & テスト計画

- [x] Google Analytics（`_ga`）やCSRFトークン（`XSRF-TOKEN`）に対して不要なHttpOnly警告（HIGH/MEDIUM）が発生しないこと。
- [x] `default-src 'self'` のみ定義され `script-src` が未定義のWebページにおいて、正しく安全（PASS）と判定されること。
- [x] `__Host-` プレフィックスを持ちながら `path=/` でないCookieが確実に `FAIL` 判定されること。
- [x] 調査時に拡張機能起動前の初期通信が未取得の場合、Coverageステータスが `partial` と記録されること。
- [x] Vitest単体テスト（`cookies.test.ts`, `csp-parser.test.ts`, `coverage.test.ts`）がすべてパスすること。
