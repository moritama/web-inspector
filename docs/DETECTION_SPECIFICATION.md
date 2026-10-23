# Web Technology & Security Inspector 技術検出仕様および判定基準書

**対象バージョン：** v1.6.0  
**最終更新日：** 2026年10月24日  
**対象コンポーネント：** `src/detection/` (ルール定義・判定エンジン・推論エンジン)

---

## 1. 基本設計方針と判定アーキテクチャ

本ツール（Web Inspector）は、Webサイトの閲覧時に発生するHTTP通信やDOM構造、JavaScript実行環境の情報を**完全に受動的（パッシブ）に観測**し、背後で稼働または利用されている技術スタックを特定します。

### 1.1 受動的調査の原則（Passive Inspection Only）
- **追加リクエストの非送信**: 脆弱性探索やプロービング（`/admin/`, `/login.action` 等への能動的アクセス）は一切行わず、ユーザーが通常閲覧したページの応答データのみを利用します。
- **ローカル完結**: 判定ロジックおよび正規表現照合はすべてブラウザ内部で完結し、外部サーバーへの通信は一切行いません。
- **エビデンス（根拠）の保持**: すべての検出結果は「どのヘッダー」「どのCookie」「どのDOM要素」から判定されたかを必ず保持・明示します。

```mermaid
flowchart TD
    subgraph Browser["ブラウザ観測レイヤー (受動的収集)"]
        H["HTTPレスポンスヘッダー<br/>(Server, X-Powered-By, Set-Cookie等)"]
        C["Cookie一覧<br/>(名前・属性・プレフィックス)"]
        D["DOM & HTML構造<br/>(Meta, Script src, Link href, 特有属性)"]
        R["JS実行時グローバル変数<br/>(window.bootstrap, window.jQuery等)"]
    end

    subgraph Pass1["第1パス：直接検出エンジン (Direct Detection)"]
        DirectMatch["シグナル別正規表現・パターン照合<br/>(重みスコア加算 & バージョン抽出)"]
    end

    subgraph Pass2["第2パス：連動検知エンジン (Implication Engine)"]
        ParentChild["親技術から子技術への推論<br/>(Next.js → React, Laravel → PHP)"]
        CandidateGroup["複数候補集約<br/>(XSRF-TOKEN → Laravel/Spring/Node)"]
        StatusAssign["ランタイム状態の付与<br/>(confirmed / possible / unknown / N/A)"]
    end

    subgraph Result["判定出力 (3層モデル)"]
        O_Direct["直接検出 (direct)<br/>確信度 70〜100%"]
        O_Inferred["連動検知 (inferred)<br/>確信度 親に準拠"]
        O_Assoc["複数候補 (associated)<br/>集約1行表示"]
    end

    Browser --> DirectMatch
    DirectMatch --> ParentChild
    ParentChild --> CandidateGroup
    CandidateGroup --> StatusAssign
    StatusAssign --> O_Direct
    StatusAssign --> O_Inferred
    StatusAssign --> O_Assoc
```

---

## 2. 判定シグナルの種類と確信度計算

### 2.1 7種類の検出シグナル分類
各技術の検出ルールは、以下の7種類のシグナル（`RuleSignal`）を組み合わせて定義されています。

| シグナル種別 (`type`) | 観測対象 (`target`) | 特徴と判定精度 |
| :--- | :--- | :--- |
| **`header`** | HTTPレスポンスヘッダー名 | `Server`, `X-Powered-By` など。明示的に宣言されている場合、極めて確信度が高い（重み 85〜95）。 |
| **`cookie`** | Cookieの名前 | `PHPSESSID`, `laravel_session`, `JSESSIONID` など。セッション命名規則から高い確度で特定可能。 |
| **`script`** | `<script>` タグの `src` URL | 外部CDN（jsdelivr等）やライブラリ特有のファイルパス。バージョン特定にも寄与。 |
| **`link`** | `<link>` タグの `href` URL | スタイルシート（CSS）やアイコン、WordPress REST APIリンクなど。 |
| **`meta`** | `<meta>` タグの `name` / `content` | `<meta name="generator" content="WordPress 6.4">` など。CMSやSSGの直接エビデンス。 |
| **`dom`** | DOMセレクタ / HTML要素 | 特有の属性（`[data-reactroot]`, `[ng-version]`）、CSRFトークン隠しフィールド、固有classなど。 |
| **`runtime`** | JavaScript実行時オブジェクト | `window.bootstrap.Modal.VERSION` など、ブラウザ実行メモリから直接抽出するため確信度100%。 |

### 2.2 確信度スコア（Confidence Score）の計算基準
- 単一のシグナルで確定できる決定打（`Server` ヘッダーや `generator` メタ等）には **85〜95点** の重みを付与します。
- 補助的なシグナル（一般的なCookie名、DOMクラス等）には **30〜60点** の重みを付与します。
- 複数のシグナルが同時に合致した場合はスコアを加算し、**上限は 100%** とします。
- 原則として、総合確信度が **60% 以上** の場合に技術リストへ採用されます。

### 2.3 ランタイム稼働状態（Runtime Status）の4区分
v1.6.0で導入されたImplication Engineでは、技術の性質に応じて以下の稼働状態を明記します。

| 状態値 | ラベル表示 | 定義・判定基準 | 代表例 |
| :--- | :--- | :--- | :--- |
| **`confirmed`** | 稼働確認済 | ブラウザ上で実行が直接確認された技術 | React, Vue.js, jQuery, Bootstrap (JS) |
| **`possible`** | 稼働可能性あり | シグナルは存在するが、静的配信やプロキシの可能性がある技術 | Node.js (SSRか静的SSGか外部観測のみでは断定不可) |
| **`unknown`** | 稼働未確認 | バックエンド側で実行されているが、クライアントから内部状態を観測できない技術 | PHP, Java, Python, Ruby, C# |
| **`not-applicable`**| 対象外 | ランタイムの概念を持たない純粋なクライアントUI・CSSなど | Tailwind CSS, Bootstrap (CSSのみ), Font Awesome |

---

## 3. 全調査対象技術 判定基準カタログ (50技術)

### 3.1 Webサーバー (`web-server`)
Webサーバーは主にHTTPレスポンスの `Server` ヘッダーを主たるエビデンスとして判定します。

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | バージョン抽出方法 | 重み |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `apache` | **Apache** | `header`: `server` | `Apache(?:/([0-9.]+))?` | `Apache/([0-9.]+)` より抽出 | 95 |
| `nginx` | **Nginx** | `header`: `server` | `nginx(?:/([0-9.]+))?` | `nginx/([0-9.]+)` より抽出 | 95 |
| `iis` | **Microsoft-IIS** | `header`: `server` | `Microsoft-IIS(?:/([0-9.]+))?` | `Microsoft-IIS/([0-9.]+)` より抽出 | 95 |
| `litespeed` | **LiteSpeed** | `header`: `server` | `LiteSpeed` | - | 95 |
| `caddy` | **Caddy** | `header`: `server` | `Caddy` | - | 95 |

---

### 3.2 プログラミング言語・ランタイム (`programming-language`)
バックエンド言語は受動的調査では実行状態を直接観測できないため、連動検知された場合は `unknown`（稼働未確認）として安全に扱われます。

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | バージョン抽出方法 | 重み | 連動推論 (Implication) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `php` | **PHP** | `header`: `x-powered-by`<br>`header`: `server`<br>`cookie`: `PHPSESSID`<br>`url`: `path` | `PHP(?:/([0-9.]+))?`<br>`PHP(?:/([0-9.]+))?`<br>`^PHPSESSID$`<br>`\.php(?:$\|\?)` | ヘッダー内 `PHP/([0-9.]+)` より抽出 | 95<br>85<br>55<br>50 | - |
| `aspnet` | **ASP.NET** | `header`: `x-aspnet-version`<br>`header`: `x-aspnetmvc-version`<br>`header`: `x-powered-by`<br>`cookie`: `.ASPXAUTH`<br>`cookie`: `ASP.NET_SessionId`<br>`url`: `path` | `^([0-9.]+)$`<br>`^([0-9.]+)$`<br>`ASP\.NET`<br>`^\.ASPXAUTH$`<br>`^ASP\.NET_SessionId$`<br>`\.(?:aspx\|axd\|asmx)(?:$\|\?)` | ヘッダー値より抽出 | 95<br>95<br>90<br>70<br>65<br>60 | - |
| `java` | **Java** | `header`: `x-powered-by`<br>`cookie`: `JSESSIONID`<br>`cookie`: `XSRF-TOKEN`<br>`url`: `path` | `(?:Servlet\|JSP\|Tomcat\|JBoss\|WildFly)`<br>`^JSESSIONID$`<br>`^XSRF-TOKEN$`<br>`\.(?:jsp\|jspx\|do\|action)(?:$\|\?)` | - | 85<br>60<br>35<br>55 | - |
| `python` | **Python** | `header`: `server` | `Python(?:/([0-9.]+))?` | `Python/([0-9.]+)` より抽出 | 85 | - |
| `ruby` | **Ruby** | `header`: `x-powered-by` | `Phusion Passenger.*Ruby` | - | 85 | - |
| `nodejs` | **Node.js** | `header`: `x-powered-by`<br>`header`: `server`<br>`cookie`: `connect.sid`<br>`cookie`: `XSRF-TOKEN` | `Node\.js(?:/([0-9.]+))?`<br>`Node\.js(?:/([0-9.]+))?`<br>`^connect\.sid$`<br>`^XSRF-TOKEN$` | `Node\.js/([0-9.]+)` より抽出 | 90<br>90<br>80<br>35 | - |

---

### 3.3 バックエンドフレームワーク (`programming-language` / `framework`)
フレームワークが検出された場合、Implication Engine により背後のプログラミング言語が連動検出されます。

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | バージョン抽出方法 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `laravel` | **Laravel** | `header`: `x-powered-by`<br>`cookie`: `laravel_session`<br>`cookie`: `XSRF-TOKEN` | `Laravel(?:/([0-9.]+))?`<br>`laravel_session`<br>`^XSRF-TOKEN$` | `Laravel/([0-9.]+)` より抽出 | 95<br>85<br>35 | $\rightarrow$ **PHP** (`unknown`) |
| `spring-boot` | **Spring Boot** | `header`: `x-application-context`<br>`dom`: `body`<br>`script`: `src` | 存在一致 (`.*`)<br>`Whitelabel Error Page`<br>`spring-boot` | - | 95<br>90<br>80 | $\rightarrow$ **Java** (`unknown`) |
| `aspnet-core` | **ASP.NET Core**| `cookie`: `.AspNetCore.Antiforgery.`<br>`cookie`: `.AspNetCore.Session`<br>`cookie`: `.AspNetCore.Cookies`<br>`header`: `server` | `^\.AspNetCore\.Antiforgery\.`<br>`^\.AspNetCore\.Session$`<br>`^\.AspNetCore\.Cookies$`<br>`Kestrel` | - | 90<br>90<br>90<br>90 | $\rightarrow$ **ASP.NET** (`unknown`) |
| `express` | **Express** | `header`: `x-powered-by` | `Express` | - | 95 | $\rightarrow$ **Node.js** (`unknown`) |
| `fastapi` | **FastAPI** | `dom`: `title`<br>`header`: `x-fastapi` | `FastAPI - Swagger UI\|FastAPI - ReDoc`<br>存在一致 (`.*`) | - | 95<br>90 | $\rightarrow$ **Python** (`unknown`) |
| `symfony` | **Symfony** | `cookie`: `symfony`<br>`cookie`: `sf_redirect`<br>`header`: `x-debug-token` | `^symfony$`<br>`^sf_redirect$`<br>存在一致 (`.*`) | - | 85<br>85<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `flask` | **Flask** | `header`: `server` | `Werkzeug(?:/([0-9.]+))?` | `Werkzeug/([0-9.]+)` より抽出 | 80 | $\rightarrow$ **Python** (`unknown`) |
| `nestjs` | **NestJS** | `header`: `x-powered-by` | `Nest(?:/([0-9.]+))?` | `Nest/([0-9.]+)` より抽出 | 90 | $\rightarrow$ **Node.js** (`unknown`) |
| `fastify` | **Fastify** | `header`: `x-fastify-` | 存在一致 (`.*`) | - | 90 | $\rightarrow$ **Node.js** (`unknown`) |
| `cakephp` | **CakePHP** | `cookie`: `CAKEPHP` | `^CAKEPHP$` | - | 85 | $\rightarrow$ **PHP** (`unknown`) |
| `spring-security`| **Spring Security**| `dom`: `input[name='_csrf']` | `_csrf` | - | 60 | $\rightarrow$ **Java** (`unknown`) |
| `python-django` | **Django** | `dom`: `input[name='csrfmiddlewaretoken']`<br>`cookie`: `csrftoken` | `csrfmiddlewaretoken`<br>`^csrftoken$` | - | 80<br>40 | $\rightarrow$ **Python** (`unknown`) |
| `ruby-on-rails` | **Ruby on Rails** | `header`: `x-powered-by`<br>`dom`: `meta[name='csrf-param']` | `Phusion Passenger`<br>`authenticity_token` | - | 80<br>70 | $\rightarrow$ **Ruby** (`unknown`) |

---

### 3.4 CMS（コンテンツマネジメントシステム） (`cms`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | バージョン抽出方法 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `wordpress` | **WordPress** | `meta`: `generator`<br>`header`: `link`<br>`script`: `src`<br>`link`: `href` | `WordPress(?:\s+([0-9.]+))?`<br>`<https?://[^>]+/wp-json/>; rel="https://api\.w\.org/"`<br>`/wp-includes/\|/wp-content/`<br>`/wp-content/\|/wp-includes/\|/wp-json/` | `WordPress\s+([0-9.]+)` より抽出 | 95<br>85<br>85<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `drupal` | **Drupal** | `meta`: `generator`<br>`header`: `x-generator`<br>`header`: `x-drupal-cache`<br>`script`: `src` | `Drupal(?:\s+([0-9.]+))?`<br>`Drupal(?:\s+([0-9.]+))?`<br>存在一致 (`.*`)<br>`/sites/default/files/\|/misc/drupal\.js` | `Drupal\s+([0-9.]+)` より抽出 | 95<br>95<br>85<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `joomla` | **Joomla** | `meta`: `generator`<br>`script`: `src` | `Joomla!(?:\s+([0-9.]+))?`<br>`/media/system/js/\|/media/jui/js/` | `Joomla!\s+([0-9.]+)` より抽出 | 95<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `shopify` | **Shopify** | `header`: `server`<br>`script`: `src`<br>`link`: `href` | `cloudflare.*shopify\|Shopify`<br>`cdn\.shopify\.com`<br>`cdn\.shopify\.com` | - | 90<br>90<br>85 | - |
| `wix` | **Wix** | `meta`: `generator`<br>`header`: `x-wix-request-id`<br>`script`: `src` | `Wix\.com`<br>存在一致 (`.*`)<br>`static\.wixstatic\.com` | - | 95<br>95<br>90 | - |

---

### 3.5 フロントエンドフレームワーク・UIライブラリ (`js-framework`, `js-css-library`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | バージョン抽出方法 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `react` | **React** | `dom`: `[data-reactroot], [data-reactid]`<br>`script`: `src` | `data-react`<br>`/react(?:\.production\.min\|\.development)?\.js\|react-dom` | - | 90<br>85 | - |
| `nextjs` | **Next.js** | `dom`: `script#__NEXT_DATA__`<br>`header`: `x-powered-by`<br>`script`: `src`<br>`link`: `href` | `__NEXT_DATA__`<br>`Next\.js`<br>`/_next/static/`<br>`/_next/static/` | - | 95<br>95<br>90<br>85 | $\rightarrow$ **React** (`N/A`)<br>$\rightarrow$ **Node.js** (`unknown`) |
| `vue` | **Vue.js** | `dom`: `[data-v-]`<br>`script`: `src`<br>`dom`: `#__nuxt` | `data-v-`<br>`/vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js`<br>`__nuxt` | - | 90<br>85<br>70 | - |
| `nuxtjs` | **Nuxt** | `dom`: `#__nuxt, script#__NUXT_DATA__`<br>`script`: `src`<br>`link`: `href` | `__nuxt\|__NUXT_DATA__`<br>`/_nuxt/`<br>`/_nuxt/` | - | 95<br>90<br>85 | $\rightarrow$ **Vue.js** (`N/A`)<br>$\rightarrow$ **Node.js** (`unknown`) |
| `angular` | **Angular** | `dom`: `[ng-version]`<br>`dom`: `[ng-app], [ng-controller]`<br>`script`: `src` | `ng-version="([0-9.]+)"`<br>`ng-`<br>`angular(?:\.min)?\.js` | `ng-version="([0-9.]+)"` より抽出 | 95<br>85<br>80 | - |
| `svelte` | **Svelte** | `dom`: `[class*='svelte-']`<br>`script`: `src` | `svelte-`<br>`/_app/immutable/` | - | 90<br>75 | - |
| `sveltekit` | **SvelteKit** | `dom`: `script[data-sveltekit-], div#svelte` | `data-sveltekit\|__sveltekit\|_app/immutable` | - | 95 | $\rightarrow$ **Svelte** (`N/A`)<br>$\rightarrow$ **Node.js** (`unknown`) |
| `astro` | **Astro** | `dom`: `[data-astro-cid-], astro-island`<br>`meta`: `generator` | `data-astro-cid-\|astro-island`<br>`Astro(?:\s+v?([0-9.]+))?` | `Astro(?:\s+v?([0-9.]+))` より抽出 | 95<br>95 | $\rightarrow$ **Node.js** (`unknown`) |
| `alpine` | **Alpine.js** | `dom`: `[x-data], [x-init], [x-bind]`<br>`script`: `src` | `x-data\|x-init\|x-bind`<br>`alpine(?:\.min)?\.js` | - | 90<br>85 | - |
| `htmx` | **htmx** | `dom`: `[hx-get], [hx-post], [hx-target]`<br>`script`: `src` | `hx-get\|hx-post\|hx-target\|hx-swap`<br>`htmx(?:\.org)?(?:\.min)?\.js` | - | 90<br>85 | - |
| `jquery` | **jQuery** | `runtime`: `window.jQuery.fn.jquery`<br>`script`: `src` (バージョン付き)<br>`script`: `src` | 実行時変数取得<br>`jquery[.-]([0-9.]+)(?:\.min)?\.js`<br>`jquery(?:\.min)?\.js` | JS変数またはファイル名より抽出 | 95<br>90<br>75 | - |
| `bootstrap` | **Bootstrap** | `runtime`: `window.bootstrap.Modal.VERSION`<br>`runtime`: `jQuery.fn.modal.Constructor.VERSION`<br>`link`: `href`<br>`script`: `src` | v5実行時変数取得<br>v4実行時変数取得<br>`bootstrap(?:\.min)?\.css`<br>`bootstrap(?:\.bundle)?(?:\.min)?\.js` | JS実行時変数、URLパス、クエリ (`?v=X`) より抽出 | 95<br>95<br>85<br>80 | - |
| `tailwind` | **Tailwind CSS** | `script`: `src`<br>`css`: `class` | `tailwindcss\|cdn\.tailwindcss\.com`<br>`(?:flex\|grid\|hidden)\s+(?:items-\|space-\|p-\|bg-)` | - | 90<br>80 | - |
| `material-ui` | **Material UI** | `dom`: `[class*='MuiButton-']` 等 | `Mui[A-Z][a-zA-Z]+-` | - | 85 | $\rightarrow$ **React** (`N/A`) |
| `datatables` | **DataTables** | `script`: `src`<br>`dom`: `table.dataTable`<br>`link`: `href` | `(?:jquery\.)?dataTables(?:\.min)?\.js`<br>`dataTable\|dataTables_wrapper`<br>`(?:jquery\.)?dataTables.*\.css` | - | 90<br>85<br>80 | - |
| `chartjs` | **Chart.js** | `script`: `src` | `chart(?:\.umd)?(?:\.min)?\.js` | - | 85 | - |
| `axios` | **Axios** | `script`: `src` | `axios(?:\.min)?\.js` | - | 85 | - |
| `d3` | **D3.js** | `script`: `src` | `d3(?:\.v[0-9]+)?(?:\.min)?\.js` | - | 85 | - |
| `tinymce` | **TinyMCE** | `dom`: `.tox-tinymce, .mce-tinymce`<br>`script`: `src` | `tox-tinymce\|mce-tinymce`<br>`tinymce(?:\.min)?\.js` | - | 90<br>85 | - |
| `ckeditor` | **CKEditor** | `dom`: `.ck-editor, .cke`<br>`script`: `src` | `ck-editor\|cke_`<br>`ckeditor(?:\.min)?\.js` | - | 90<br>85 | - |
| `fontawesome` | **Font Awesome** | `link`: `href`<br>`dom`: `i[class*='fa-']` | `font-awesome\|fontawesome\|all(?:\.min)?\.css`<br>`fa-\|fas \|fab ` | - | 85<br>70 | - |

---

### 3.6 クラウドホスティング・外部サービス・解析・セキュリティ (`hosting-cloud`, `analytics-tracking`, `security-service`)

| 技術ID | 技術名 | カテゴリ | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `vercel` | **Vercel** | `hosting-cloud` | `header`: `server`<br>`header`: `x-vercel-id`<br>`header`: `x-vercel-cache` | `^Vercel$`<br>存在一致 (`.*`)<br>存在一致 (`.*`) | 95<br>95<br>90 |
| `netlify` | **Netlify** | `hosting-cloud` | `header`: `server`<br>`header`: `x-nf-request-id` | `^Netlify$`<br>存在一致 (`.*`) | 95<br>95 |
| `firebase-hosting`| **Firebase Hosting** | `hosting-cloud` | `header`: `x-firebase-hosting` | 存在一致 (`.*`) | 95 |
| `azure-app-service`| **Azure App Service** | `hosting-cloud` | `cookie`: `ARRAffinity`<br>`cookie`: `ARRAffinitySameSite` | `^ARRAffinity$`<br>`^ARRAffinitySameSite$` | 90<br>90 |
| `aws-alb` | **AWS ALB** | `hosting-cloud` | `cookie`: `AWSELB`<br>`cookie`: `AWSELBCORS` | `^AWSELB$`<br>`^AWSELBCORS$` | 90<br>90 |
| `aws-api-gateway` | **AWS API Gateway** | `hosting-cloud` | `header`: `x-amz-apigw-id`<br>`header`: `x-amzn-requestid` | 存在一致 (`.*`)<br>存在一致 (`.*`) | 95<br>85 |
| `google-analytics`| **Google Analytics** | `analytics-tracking`| `script`: `src`<br>`cookie`: `_ga` | `google-analytics\.com/(?:analytics\|ga)\.js\|googletagmanager\.com/gtag/js`<br>`^_ga$` | 90<br>85 |
| `google-tag-manager`| **Google Tag Manager**| `analytics-tracking`| `script`: `src`<br>`dom`: `iframe` | `googletagmanager\.com/gtm\.js`<br>`googletagmanager\.com/ns\.html` | 95<br>95 |
| `microsoft-clarity`| **Microsoft Clarity** | `analytics-tracking`| `script`: `src`<br>`cookie`: `_clck` | `clarity\.ms/tag/`<br>`^_clck$` | 95<br>85 |
| `sentry` | **Sentry** | `security-service` | `script`: `src` | `browser\.sentry-cdn\.com\|js\.sentry-cdn\.com` | 95 |
| `recaptcha` | **reCAPTCHA** | `security-service` | `script`: `src`<br>`dom`: `.g-recaptcha` | `google\.com/recaptcha/api\.js\|recaptcha/enterprise\.js`<br>`g-recaptcha` | 95<br>90 |
| `hcaptcha` | **hCaptcha** | `security-service` | `script`: `src`<br>`dom`: `.h-captcha` | `hcaptcha\.com/1/api\.js\|js\.hcaptcha\.com`<br>`h-captcha` | 95<br>90 |

---

### 3.7 CDN / WAF (`cdn-waf`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- |
| `cloudflare` | **Cloudflare** | `header`: `server`<br>`header`: `cf-ray`<br>`header`: `cf-cache-status`<br>`cookie`: `__cf_bm` | `cloudflare`<br>存在一致 (`.*`)<br>存在一致 (`.*`)<br>`^__cf_bm$` | 95<br>95<br>90<br>85 |
| `cloudfront` | **Amazon CloudFront** | `header`: `x-amz-cf-id`<br>`header`: `via`<br>`header`: `x-cache` | 存在一致 (`.*`)<br>`CloudFront`<br>`(?:Hit\|Miss\|Error) from cloudfront` | 95<br>95<br>90 |
| `fastly` | **Fastly** | `header`: `fastly-debug-digest`<br>`header`: `x-fastly-request-id`<br>`header`: `x-served-by` | 存在一致 (`.*`)<br>存在一致 (`.*`)<br>`cache-[a-z0-9]+` | 95<br>95<br>85 |
| `akamai` | **Akamai** | `header`: `server`<br>`header`: `x-akamai-transformed` | `AkamaiGHost`<br>存在一致 (`.*`) | 95<br>95 |

---

## 4. Implication Engine（連動推論）連動マトリクス

Implication Engine は、親技術が直接検出された際に、依存関係にある子技術を自動的に補完する第2パスエンジンです。

```mermaid
graph LR
    Next["Next.js"] -->|"framework-dependency (N/A)"| React["React"]
    Next -->|"possible-runtime (unknown)"| Node["Node.js"]
    
    Nuxt["Nuxt"] -->|"framework-dependency (N/A)"| Vue["Vue.js"]
    Nuxt -->|"possible-runtime (unknown)"| Node
    
    SvelteKit["SvelteKit"] -->|"framework-dependency (N/A)"| Svelte["Svelte"]
    SvelteKit -->|"possible-runtime (unknown)"| Node
    
    MUI["Material UI"] -->|"framework-dependency (N/A)"| React
    
    Laravel["Laravel"] -->|"runtime-dependency (unknown)"| PHP["PHP"]
    Symfony["Symfony"] -->|"runtime-dependency (unknown)"| PHP
    CakePHP["CakePHP"] -->|"runtime-dependency (unknown)"| PHP
    WP["WordPress"] -->|"runtime-dependency (unknown)"| PHP
    Drupal["Drupal"] -->|"runtime-dependency (unknown)"| PHP
    
    Spring["Spring Boot"] -->|"runtime-dependency (unknown)"| Java["Java"]
    FastAPI["FastAPI"] -->|"runtime-dependency (unknown)"| Python["Python"]
    Django["Django"] -->|"runtime-dependency (unknown)"| Python
    Flask["Flask"] -->|"runtime-dependency (unknown)"| Python
    Rails["Ruby on Rails"] -->|"runtime-dependency (unknown)"| Ruby["Ruby"]
    Express["Express"] -->|"runtime-dependency (unknown)"| Node
    Fastify["Fastify"] -->|"runtime-dependency (unknown)"| Node
    ASPCore["ASP.NET Core"] -->|"framework-dependency (unknown)"| ASP["ASP.NET"]
```

### 連動推論ルール一覧
1. **確信度上限クリップ**: 推論先の確信度は、推論元技術の確信度を超えないよう制御されます（$Score_{child} \le Score_{parent} \times Factor$）。
2. **循環防止**: `visitedEdges` によるトポロジカル探索を行い、`A -> B -> A` のような無限ループを完全に抑止します。
3. **静的配信への配慮**: Next.js や Nuxt、Astro からの Node.js 推論は、Vercel 等の静的ホスティング（SSG）で配信されている可能性を考慮し、**「稼働未確認 (`unknown`)」**として記録します。

---

## 5. XSRF-TOKEN 等の複数候補集約ロジック (Associated Candidates)

SPA（Single Page Application）構成において、CSRF対策Cookieとして広く採用されている `XSRF-TOKEN` は、単独ではフレームワークを一意に特定できません。

```mermaid
sequenceDiagram
    autonumber
    actor User as ユーザー / ブラウザ
    participant Engine as 判定エンジン
    participant UI as ポップアップ / ダッシュボード

    Note over User,Engine: 状態A: Cookie「XSRF-TOKEN」のみ検出された場合
    User->>Engine: Cookie一覧 { XSRF-TOKEN: ... }
    Engine->>Engine: Laravel, Spring Boot, Node.js に低い重み(35点)付与
    Engine->>UI: 1行に集約して表示<br/>「Laravel / Spring Boot / Node.js (関連候補)」

    Note over User,Engine: 状態B: Laravel固有のCookieが後から見つかった場合
    User->>Engine: Cookie一覧 { XSRF-TOKEN, laravel_session }
    Engine->>Engine: Laravel の確信度が一気に95%に上昇
    Engine->>Engine: 候補群 (Spring / Node) を自動解消
    Engine->>UI: 「Laravel (直接検出 95%)」に確定昇格
```

- **集約のメリット**: 1つのCookieに対して3つの技術がバラバラに表示されて画面が埋まるノイズを防止します。
- **自動解消（Resolution）**: いずれかの技術に固有のシグナル（例: `laravel_session`, `JSESSIONID`, `X-Powered-By: Express` 等）が検出された瞬間、候補状態は即座に解除され、特定された技術のみが本採用されます。

---

## 6. バージョン特定・隠蔽時の挙動とセキュリティ設計

### 6.1 バージョン特定ができる条件・できない条件
Web Inspector では、受動的調査の原則に従ってバージョンを抽出します。

| 調査対象 | バージョン特定が成功する条件 | バージョンが「不明」となる要因（隠蔽） |
| :--- | :--- | :--- |
| **Apache / Nginx** | `Server` ヘッダーに `Apache/2.4.52` と明記 | `ServerTokens Prod` により `Server: Apache` のみ出力されている場合 |
| **PHP** | `X-Powered-By: PHP/8.2.1` が出力されている | `expose_php = Off` によりヘッダーが非表示化されている場合 |
| **WordPress** | `<meta name="generator" content="WordPress 6.4.2">` が存在 | テーマやセキュリティプラグインで generator タグが除去されている場合 |
| **Bootstrap** | `window.bootstrap.Modal.VERSION` または CDN URL にバージョン記載 | Webpack等でバンドル・minifyされ、CSSクラスのみ使用されている場合 |
| **Angular** | DOMに `ng-version="16.2.0"` 属性が存在 | 本番ビルド時に属性が剥離されている場合 |

### 6.2 EOL / CVE 照合における安全設計
- **断定の回避**: バージョンが隠蔽されて特定できない場合は、「バージョン不明」として安全に扱い、**無関係なバージョンのCVEを誤報（False Positive）として出さない**安全機構（IMP-19）が働きます。
- **サポート状況の客観通知**: バージョンが特定できた場合のみ、オフラインEOLデータベースおよびCVEデータベースと照合し、「EOL（公式サポート終了）」または「既知の脆弱性あり」を最新バージョンへの移行ガイダンスとともに提示します。
