# Web Technology & Security Inspection Report

**対象ホスト:** `ai-portal.example.test`  
**調査実施日時:** 2026/11/1 9:00:00 (JST)  
**Inspector バージョン:** v1.7.0 (Manifest V3)  
**解析方式:** 受動的解析 (Passive Inspection) / 完全ローカル突合  

---

## 1. 調査概要

| 項目 | 内容 |
|---|---|
| 対象URL | `https://ai-portal.example.test/` |
| ホスト名 | `ai-portal.example.test` |
| プロトコル | HTTPS (暗号化通信) |
| 診断ルールバージョン | 1.7.0 |
| オフライン脆弱性DBバージョン | 2026-10-31 |
| 要確認項目数 | **1 件** |
| 検出技術スタック数 | **2 件** |


## 2. 調査範囲・完全性 (Coverage)

- **完全性ステータス:** **完全 (Complete)**
- **DOM / HTML解析:** ✅ 取得成功
- **HTTPレスポンスヘッダー:** ✅ 取得成功
- **Cookie属性情報:** ✅ 取得成功 (5 個観測)
- **ネットワーク・通信解析:** ✅ 取得成功



## 3. 調査結果サマリー

### セキュリティ指摘レベル内訳
| 重大度 | 指摘件数 | 説明 |
|:---:|:---:|---|
| **CRITICAL (緊急)** | **0** | 悪用確認済み脆弱性（CISA KEV）または緊急度の高い深刻な脆弱性 |
| **HIGH (危険)** | **0** | 直ちに対応・修正が推奨される設定不備・脆弱性 |
| **MEDIUM (警告)** | **0** | セキュリティ基準に抵触、またはサポート終了の技術 |
| **LOW (注意)** | **1** | 改善が望ましい設定上の軽微な不備 |
| **INFO (情報)** | **5** | 参考情報・問題のない項目 |


## 4. 検出技術スタック

> [!NOTE]
> **受動的調査の原則と推定関係:** 固有シグナルから直接検出された技術と、依存関係から連動検知された技術を明確に区分しています。外部からの受動観測ではサーバー内部の実行状態を直接観測できない技術は「稼働未確認」として記録しています。

| 技術名 | カテゴリ | バージョン | ディストリ版 | 検出方式 | 連動元 / 種別 | ランタイム状態 | 確信度 | 整合性 |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **ASP.NET** | programming-language | `v4.0.30319` | - | 直接検出 | - | 稼働確認済 | high (95%) | - |
| **Microsoft IIS** | web-server | `v10.0` | - | 直接検出 | - | 稼働確認済 | high (95%) | - |


## 5. セキュリティ診断結果

| 診断項目 | ステータス | 重大度 | 観測値 | 許容状態 |
|---|:---:|:---:|---|:---:|
| HTTPS暗号化通信 | PASS | INFO | `HTTPSで接続（証明書の有効性は対象外）` | - |
| HSTS (Strict-Transport-Security) | PASS | INFO | `max-age=31536000; includeSubDomains` | - |
| X-Frame-Options | PASS | INFO | `SAMEORIGIN` | - |
| X-Content-Type-Options | PASS | INFO | `nosniff` | - |
| Referrer-Policy | INFO | INFO | `ヘッダー未設定（ブラウザ既定: strict-origin-when-cross-origin 相当）` | - |
| 一般CookieのSecure属性欠落 | **WARN** | LOW | `ai_user, ai_session (計 2 件に Secure 属性なし)` | - |


## 6. EOL・既知脆弱性情報 (ライブラリセキュリティ)

> [!IMPORTANT]
> オフライン脆弱性DBスナップショット (2026-10-31) とのローカル突合結果です。未登録の技術は「安全」を意味するものではありません。

| 対象技術 | バージョン | ディストリ版 | サポート状況 (EOL) | 照合ステータス | 該当CVE/GHSA | 修正状況 (fixStatus) | CISA KEV | 推奨対応 |
|---|:---:|:---:|:---:|:---:|---|---|:---:|---|
| **ASP.NET** | `4.0.30319` | - | Supported | この技術の脆弱性は収録していません | - | - | - | 評価不可（収録対象外） |
| **Microsoft IIS** | `10.0` | - | Supported | この技術の脆弱性は収録していません | - | - | - | 評価不可（収録対象外） |


## 7. Cookie属性診断

※ **セキュリティ保護:** Cookieの値（Value）および認証シークレットは一切収集・出力していません。
※ **親ドメインのCookieに関する注記:** 親ドメイン（上位ドメイン）をスコープとするCookieが含まれる場合、同一ドメイン配下の別サイト・別ページで発行された可能性があり、このページが設定したとは限らない点にご留意ください。

| Cookie名 | ドメイン | パス | 用途分類 | Secure | HttpOnly | SameSite | CHIPS (Partitioned) |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
| `ASP.NET_SessionId` | `ai-portal.example.test` | `/` | authentication | Yes | Yes | `lax` | No |
| `__RequestVerificationToken` | `ai-portal.example.test` | `/` | csrf | Yes | **No** | `lax` | No |
| `ai_user` | `ai-portal.example.test` | `/` | analytics | **No** | **No** | `lax` | No |
| `ai_session` | `ai-portal.example.test` | `/` | analytics | **No** | **No** | `lax` | No |
| `ApplicationGatewayAffinity` | `ai-portal.example.test` | `/` | general | Yes | Yes | `lax` | No |


## 8. CSP（Content Security Policy）診断

- **CSPポリシー保持件数:** 0 件
> CSPヘッダーまたはmetaタグによるCSPは設定されていません。


## 9. 外部通信先・サードパーティ分析 (Public Suffix List / eTLD+1)

- **総通信先ホスト数:** 2 件
- **First-Party (同一組織・自社ドメイン):** 1 件
- **Third-Party (外部サービス通信先):** 1 件

| 接続先ホスト名 | 登録可能ドメイン (eTLD+1) | 所属種別 | 推定カテゴリ | 観測リソース数 |
|---|---|:---:|:---:|:---:|
| `ai-portal.example.test` | `example.test` | First-Party | `other` | 1 |
| `js.monitor.azure.com` | `azure.com` | **Third-Party** | `analytics` | 1 |


## 10. 前回調査との差分 (Diff)

> 前回調査レポートとの比較は実行されていません（初回調査または単一レポート出力）。


## 11. 差分発生原因の推定分析

> 比較未実行のため対象外です（前回調査レポートとの比較は実行されていません）。


## 12. 診断項目の許容・除外設定 (Finding Exceptions)

> 現在適用されている許容・除外設定はありません。


## 13. 推奨対応ロードマップ

1. **継続的改善 (LOW):**
   - **一般CookieのSecure属性欠落**: HTTPSサイトでは、すべてのCookieに Secure 属性を付与して平文通信での送信を防止してください。


## 14. 検出根拠 (エビデンス詳細)


### ASP.NET (確信度: high - 95%)
- **[response-header]** `X-AspNet-Version`: `4.0.30319` 


### Microsoft IIS (確信度: high - 95%)
- **[response-header]** `Server`: `Microsoft-IIS/10.0` 



## 15. 調査上の制限事項・免責事項

1. **受動的解析のスコープ:**
   本拡張機能は、ブラウザが通常のWeb閲覧時に受信したHTML、CSS、JavaScript、HTTPヘッダー、Cookie属性のみを受動的に解析（Passive Inspection）しています。外部サーバーへの攻撃的なリクエスト送信や内部ソースコードの監査は行っていません。
2. **脆弱性DBの網羅性:**
   オフライン脆弱性DBに未収録のライブラリや独自フレームワークについて「脆弱性なし」と判定されていても、安全性を完全に保証するものではありません。
3. **認証後ページの扱い:**
   ログインや特定セッションを必要とする深層ページは、閲覧した範囲に限定して診断されます。
4. **機密情報の非保持:**
   Cookieの値、認証トークン、Authorizationヘッダーなどのシークレット情報はメモリ保持およびレポート出力から完全に除外されています。
