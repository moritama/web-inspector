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
        O_Direct["直接検出 (direct)<br/>確信度 高/中/低"]
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

### 2.1 9種類の検出シグナル分類
各技術の検出ルールは、以下の9種類のシグナル（`RuleSignal`）を組み合わせて定義されています。

| シグナル種別 (`type`) | 観測対象 (`target`) | 特徴と判定精度 |
| :--- | :--- | :--- |
| **`header`** | HTTPレスポンスヘッダー名 | `Server`, `X-Powered-By` など。明示的に宣言されている場合、極めて確信度が高い（重み 85〜95）。 |
| **`cookie`** | Cookieの名前 | `PHPSESSID`, `laravel_session`, `JSESSIONID`, `AWSALB` など。セッション命名規則から高い確度で特定可能。 |
| **`script`** | `<script>` タグの `src` URL | 外部CDN（cdnjs, jsdelivr等）やライブラリ特有のファイルパス。バージョン特定にも寄与。 |
| **`link`** | `<link>` タグの `href` URL | スタイルシート（CSS）やアイコン、WordPress REST APIリンクなど。 |
| **`meta`** | `<meta>` タグの `name` / `content` | `<meta name="generator" content="WordPress 6.4">` など。CMSやSSGの直接エビデンス。 |
| **`dom`** | DOMセレクタ / HTML要素 | 特有の属性（`[data-reactroot]`, `[ng-version]`）、CSRF隠しフィールド、固有classなど。 |
| **`runtime`** | JavaScript実行時オブジェクト | `window.bootstrap.Modal.VERSION` など、ブラウザ実行メモリから直接抽出（MAINワールド注入）。 |
| **`url`** | ページURLパス / 拡張子 | `\.php$` や `\.aspx$` など、リクエストされたパス自体の特徴。 |
| **`css`** | スタイルシート / クラスパターン | Tailwind CSS 等のユーティリティクラス群の出現パターン。 |

### 2.2 確信度スコア（Confidence Score）の計算基準
本ツールは、単なる累積加算ではなく、**最大重みをベースに異なる種別のシグナルを逓減加算（Diminishing Returns）する合成ロジック**（`src/detection/confidence.ts`）を採用しています。

1. **ベーススコアの決定**: 観測されたエビデンス種別（header, cookie, html等）ごとに最大の weight を集約し、その中の最大値をベーススコアとします。
2. **追加シグナルによるボーナス加算**: 異なる種別のシグナルが存在する場合、それぞれの最大重みの **20%** をボーナスとして加算します（同種シグナルの重複カウントによる過剰加算を防止）。
3. **確信度帯（レベル）**:
   - **高 (High / 80〜100%)**: 明確な決定打シグナル（`Server` ヘッダーや `generator` メタ、実行時シンボル等）が存在する。
   - **中 (Medium / 50〜79%)**: Cookie単体（例: `PHPSESSID` 55点）や、複数の間接的シグナルが存在する。
   - **低 (Low / 1〜49%)**: 補助的なクラス名や汎用Cookie（例: `XSRF-TOKEN` 35点）など、可能性を示すシグナルのみが存在する。
   - ※エビデンスが観測された技術は、低確信度であってもノイズ抑制（複数候補集約等）を適用した上でレポートに提示されます。

### 2.3 ランタイム稼働状態（Runtime Status）の4区分
v1.6.0で導入されたImplication Engineでは、「検出方式（直接検出か連動推論か）」とは独立した軸として、技術の性質に応じた以下の稼働状態を明記します。

| 状態値 | ラベル表示 | 定義・判定基準 | 代表例 |
| :--- | :--- | :--- | :--- |
| **`confirmed`** | 稼働確認済 | ブラウザ上で直接DOMマーカーや実行時変数が観測されたクライアント技術 | React（直接検出時）, Vue.js, jQuery, Bootstrap |
| **`possible`** | 稼働可能性あり | シグナルは存在するが、静的配信やプロキシの可能性がある技術 | Node.js (SSRか静的SSGか外部観測のみでは断定不可) |
| **`unknown`** | 稼働未確認 | バックエンド側で実行されているが、クライアントから内部状態を観測できない技術 | PHP, Java, Python, Ruby, C# |
| **`not-applicable`**| 対象外 | ランタイムの概念を持たない純粋なクライアントCSS・アセット | Tailwind CSS, Bootstrap (CSSのみ), Font Awesome |

> [!NOTE]
> **Next.js / Nuxt 経由の React / Vue の扱い:**  
> Next.js から連動推論された React は、ブラウザ上で実際に `[data-reactroot]` や `__NEXT_DATA__` 等が直接観測されている場合は `confirmed` と判定されます。一方、サーバーサイド側の Node.js は、Vercel 等の静的エクスポート（SSG）で配信されている可能性を考慮し、SSR の明確な証拠がない限り `unknown`（稼働未確認）として安全に扱われます。

---

## 3. 全調査対象技術 判定基準カタログ (計68技術)

> [!NOTE]
> **カタログの自動整合保証:**  
> 本カタログ（第3節）は `src/detection/rules/*.json` のルール定義から直接自動生成（`npm run spec:generate`）されており、自動整合テスト (`tests/spec-integrity.test.ts`) によって100%の一致が保証されています。

### 3.1 Webサーバー (`web-server`)
Webサーバーは主にHTTPレスポンスの `Server` ヘッダーを主たるエビデンスとして判定します。

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- |
| `apache` | **Apache** | `header`: `server` | Apache(?![-\w])(?:/([0-9.]+))? | 95 |
| `nginx` | **Nginx** | `header`: `server` | nginx(?:/([0-9.]+))? | 95 |
| `iis` | **Microsoft-IIS** | `header`: `server` | Microsoft-IIS(?:/([0-9.]+))? | 95 |
| `litespeed` | **LiteSpeed** | `header`: `server` | LiteSpeed | 95 |
| `caddy` | **Caddy** | `header`: `server` | Caddy | 95 |

> [!TIP]
> **CDN・リバースプロキシによるServerヘッダーの書き換えについて:**  
> Cloudflare 等のCDNを利用している場合、オリジンの `Server: Apache` は `Server: cloudflare` に書き換えられます。一方、Amazon CloudFront 等ではオリジンのヘッダーがそのまま通過します。

---

### 3.2 プログラミング言語・ランタイム (`programming-language`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- |
| `php` | **PHP** | `header`: `x-powered-by`<br>`header`: `server`<br>`cookie`: `PHPSESSID`<br>`url`: `path` | PHP(?:/([0-9.]+))?<br>PHP(?:/([0-9.]+))?<br>^PHPSESSID$<br>\.php(?:$\|\?) | 95<br>85<br>55<br>50 |
| `aspnet` | **ASP.NET** | `header`: `x-aspnet-version`<br>`header`: `x-aspnetmvc-version`<br>`header`: `x-powered-by`<br>`cookie`: `.ASPXAUTH`<br>`cookie`: `ASP.NET_SessionId`<br>`url`: `path` | ^([0-9.]+)$<br>^([0-9.]+)$<br>ASP\.NET<br>^\.ASPXAUTH$<br>^ASP\.NET_SessionId$<br>\.(?:aspx\|axd\|asmx)(?:$\|\?) | 95<br>95<br>90<br>70<br>65<br>60 |
| `java` | **Java** | `cookie`: `JSESSIONID`<br>`cookie`: `XSRF-TOKEN`<br>`url`: `path`<br>`header`: `x-powered-by` | ^JSESSIONID$<br>^XSRF-TOKEN$<br>\.(?:jsp\|jspx\|do\|action)(?:$\|\?)<br>(?:Servlet\|JSP\|Tomcat\|JBoss\|WildFly) | 60<br>35<br>55<br>85 |
| `python` | **Python** | `header`: `server` | Python(?:/([0-9.]+))? | 85 |
| `ruby` | **Ruby** | `header`: `x-powered-by` | Phusion Passenger.*Ruby | 85 |
| `python-django` | **Django** | `cookie`: `csrftoken`<br>`dom`: `input[name='csrfmiddlewaretoken']` | ^csrftoken$<br>csrfmiddlewaretoken | 40<br>80 |
| `ruby-on-rails` | **Ruby on Rails** | `dom`: `meta[name='csrf-param']`<br>`header`: `x-powered-by` | authenticity_token<br>Phusion Passenger | 70<br>40 |
| `laravel` | **Laravel** | `header`: `x-powered-by`<br>`cookie`: `laravel_session`<br>`cookie`: `app_session`<br>`cookie`: `XSRF-TOKEN` | Laravel(?:/([0-9.]+))?<br>^laravel_session$<br>^(?!_)(?!ci_)[a-zA-Z0-9_-]+_session$<br>^XSRF-TOKEN$ | 95<br>85<br>35<br>35 |
| `nodejs` | **Node.js** | `header`: `x-powered-by`<br>`header`: `server`<br>`cookie`: `connect.sid`<br>`cookie`: `XSRF-TOKEN` | Node\.js(?:/([0-9.]+))?<br>Node\.js(?:/([0-9.]+))?<br>^connect\.sid$<br>^XSRF-TOKEN$ | 90<br>90<br>80<br>35 |
| `dotnet` | **.NET** | `header`: `server` | Kestrel | 80 |

> [!NOTE]
> **Node.js のバージョン観測とCVE/EOL照合について:**  
> Node.js のバージョンは通常本番環境のHTTPヘッダーには出力されないため、外部受動調査では「バージョン不明」となります。そのため、Node.js 向けのEOL/CVE照合は誤報防止の安全設計により原則として発火しません。

---

### 3.3 バックエンドフレームワーク (`programming-language` / `framework`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `spring-boot` | **Spring Boot** | `header`: `x-application-context`<br>`dom`: `body`<br>`script`: `src` | .*<br>Whitelabel Error Page<br>spring-boot | 95<br>90<br>80 | $\rightarrow$ **Java** (`unknown`) |
| `aspnet-core` | **ASP.NET Core** | `cookie`: `.AspNetCore.Antiforgery.`<br>`cookie`: `.AspNetCore.Session`<br>`cookie`: `.AspNetCore.Cookies`<br>`header`: `server` | ^\.AspNetCore\.Antiforgery\.<br>^\.AspNetCore\.Session$<br>^\.AspNetCore\.Cookies$<br>Kestrel | 90<br>90<br>90<br>90 | $\rightarrow$ **.NET** (`unknown`) |
| `express` | **Express** | `header`: `x-powered-by` | Express | 95 | $\rightarrow$ **Node.js** (`unknown`) |
| `fastapi` | **FastAPI** | `dom`: `title`<br>`header`: `x-fastapi` | FastAPI - Swagger UI\|FastAPI - ReDoc<br>.* | 95<br>90 | $\rightarrow$ **Python** (`unknown`) |
| `symfony` | **Symfony** | `cookie`: `symfony`<br>`cookie`: `sf_redirect`<br>`header`: `x-debug-token` | ^symfony$<br>^sf_redirect$<br>.* | 85<br>85<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `flask` | **Flask** | `header`: `server` | Werkzeug(?:/([0-9.]+))? | 80 | $\rightarrow$ **Python** (`unknown`) |
| `nestjs` | **NestJS** | `header`: `x-powered-by` | Nest(?:/([0-9.]+))? | 90 | $\rightarrow$ **Node.js** (`unknown`) |
| `fastify` | **Fastify** | `header`: `x-fastify-` | .* | 90 | $\rightarrow$ **Node.js** (`unknown`) |
| `cakephp` | **CakePHP** | `cookie`: `CAKEPHP` | ^CAKEPHP$ | 85 | $\rightarrow$ **PHP** (`unknown`) |
| `spring-security` | **Spring Security** | `dom`: `input[name='_csrf']` | _csrf | 60 | $\rightarrow$ **Java** (`unknown`) |

---

### 3.4 CMS（コンテンツマネジメントシステム） (`cms`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `wordpress` | **WordPress** | `meta`: `generator`<br>`script`: `src`<br>`link`: `href`<br>`script`: `src`<br>`link`: `href`<br>`header`: `link` | WordPress(?:\s+([0-9.]+))?<br>/wp-includes/js/wp-embed(?:\.min)?\.js(?:\?ver=([0-9.]+))?<br>/wp-includes/css/dist/block-library/style(?:\.min)?\.css(?:\?ver=([0-9.]+))?<br>/wp-includes/\|/wp-content/<br>/wp-content/\|/wp-includes/\|/wp-json/<br><https?://[^>]+/wp-json/>; rel="https://api\.w\.org/" | 95<br>90<br>90<br>85<br>80<br>85 | $\rightarrow$ **PHP** (`unknown`) |
| `drupal` | **Drupal** | `meta`: `generator`<br>`header`: `x-generator`<br>`header`: `x-drupal-cache`<br>`script`: `src` | Drupal(?:\s+([0-9.]+))?<br>Drupal(?:\s+([0-9.]+))?<br>.*<br>/sites/default/files/\|/misc/drupal\.js\|/core/misc/drupal\.js | 95<br>95<br>85<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `joomla` | **Joomla** | `meta`: `generator`<br>`script`: `src` | Joomla!(?:\s+([0-9.]+))?<br>/media/system/js/\|/media/jui/js/ | 95<br>80 | $\rightarrow$ **PHP** (`unknown`) |
| `shopify` | **Shopify** | `header`: `server`<br>`script`: `src`<br>`link`: `href` | cloudflare.*shopify\|Shopify<br>cdn\.shopify\.com<br>cdn\.shopify\.com | 90<br>90<br>85 | - |
| `wix` | **Wix** | `meta`: `generator`<br>`header`: `x-wix-request-id`<br>`script`: `src` | Wix\.com<br>.*<br>static\.wixstatic\.com | 95<br>95<br>90 | - |

---

### 3.5 フロントエンドフレームワーク・UIライブラリ (`js-framework`, `js-css-library`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み | 連動推論先 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `react` | **React** | `dom`: `[data-reactroot], [data-reactid], __reactContainer$`<br>`script`: `src` | data-react\|__reactContainer\|__reactFiber<br>(?<![\w-])react(?:-dom)?(?:@\|/v?)(\d[\d.]*)\|/react(?:\.production\.min\|\.development)?\.js\|react-dom | 90<br>85 | - |
| `nextjs` | **Next.js** | `dom`: `script#__NEXT_DATA__`<br>`script`: `src`<br>`link`: `href`<br>`header`: `x-powered-by` | __NEXT_DATA__<br>/_next/static/<br>/_next/static/<br>Next\.js | 95<br>90<br>85<br>95 | $\rightarrow$ **React** (`possible`)<br>$\rightarrow$ **Node.js** (`unknown`) |
| `vue` | **Vue.js** | `dom`: `[data-v-], [data-v-app], __vue_app__`<br>`script`: `src`<br>`dom`: `#__nuxt` | data-v-\|__vue_app__<br>(?<![\w-])vue(?:@\|/v?)(\d[\d.]*)\|/vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js<br>__nuxt | 90<br>85<br>70 | - |
| `nuxtjs` | **Nuxt** | `dom`: `#__nuxt, script#__NUXT_DATA__`<br>`script`: `src`<br>`link`: `href` | __nuxt\|__NUXT_DATA__<br>/_nuxt/<br>/_nuxt/ | 95<br>90<br>85 | $\rightarrow$ **Vue.js** (`possible`)<br>$\rightarrow$ **Node.js** (`unknown`) |
| `angular` | **Angular** | `dom`: `[ng-version]` | ng-version="([0-9.]+)" | 95 | - |
| `angularjs` | **AngularJS** | `dom`: `[ng-app], [ng-controller]`<br>`script`: `src` | \bng-(?:app\|controller\|model\|bind)\b<br>angular(?:\.min)?\.js | 90<br>85 | - |
| `svelte` | **Svelte** | `dom`: `[class*='svelte-']`<br>`script`: `src` | svelte-<br>/_app/immutable/ | 90<br>75 | - |
| `jquery` | **jQuery** | `script`: `src`<br>`script`: `src` | jquery[.-\]\([0-9.]+)(?:\.min)?\.js<br>jquery(?:\.min)?\.js | 90<br>75 | - |
| `bootstrap` | **Bootstrap** | `link`: `href`<br>`script`: `src`<br>`dom`: `.container, .row, .col-` | bootstrap(?:\.min)?\.css<br>bootstrap(?:\.bundle)?(?:\.min)?\.js<br>container | 85<br>80<br>40 | - |
| `tailwind` | **Tailwind CSS** | `css`: `class`<br>`script`: `src` | (?:sm\|md\|lg\|xl\|2xl\|hover\|focus\|dark):[a-z0-9_-]+\|[a-z0-9_-]+-\[[^\]]+\]\|(?:text\|bg\|border\|ring\|from\|to\|via)-[a-z]+-(?:50\|[1-9]00\|950)<br>tailwindcss\|cdn\.tailwindcss\.com | 70<br>90 | - |
| `alpine` | **Alpine.js** | `dom`: `[x-data], [x-init], [x-bind]`<br>`script`: `src` | x-data\|x-init\|x-bind<br>alpine(?:\.min)?\.js\|cdn\.jsdelivr\.net/npm/alpinejs | 90<br>85 | - |
| `htmx` | **htmx** | `dom`: `[hx-get], [hx-post], [hx-target], [hx-swap]`<br>`script`: `src` | hx-get\|hx-post\|hx-target\|hx-swap\|hx-trigger<br>htmx(?:\.org)?(?:\.min)?\.js | 90<br>85 | - |
| `datatables` | **DataTables** | `dom`: `table.dataTable, .dataTables_wrapper`<br>`script`: `src`<br>`link`: `href` | dataTable\|dataTables_wrapper<br>(?:jquery\.)?dataTables(?:\.min)?\.js<br>(?:jquery\.)?dataTables.*\.css | 85<br>90<br>80 | - |
| `chartjs` | **Chart.js** | `script`: `src` | (?:^\|/)chart(?:\.umd)?(?:\.min)?\.js\|/chart\.js@\|/npm/chart\.js | 85 | - |
| `axios` | **Axios** | `script`: `src` | axios(?:\.min)?\.js | 85 | - |
| `d3` | **D3.js** | `script`: `src` | (?:^\|/)d3(?:\.v[0-9]+)?(?:\.min)?\.js\|/d3@[0-9] | 85 | - |
| `tinymce` | **TinyMCE** | `dom`: `.tox-tinymce, .mce-tinymce`<br>`script`: `src` | tox-tinymce\|mce-tinymce<br>tinymce(?:\.min)?\.js | 90<br>85 | - |
| `ckeditor` | **CKEditor** | `dom`: `.ck-editor, .cke`<br>`script`: `src` | ck-editor\|cke_<br>ckeditor(?:\.min)?\.js | 90<br>85 | - |
| `fontawesome` | **Font Awesome** | `link`: `href`<br>`script`: `src`<br>`dom`: `i[class*='fa-'], [class*='fas '], [class*='fab ']` | font-?awesome\|use\.fontawesome\.com\|kit\.fontawesome\.com<br>kit\.fontawesome\.com\|font-?awesome<br>fa-\|fas \|fab  | 85<br>85<br>70 | - |
| `material-ui` | **Material UI** | `dom`: `[class*='MuiButton-'], [class*='MuiBox-'], [class*='MuiTypography-']` | Mui[A-Z][a-zA-Z]+- | 85 | $\rightarrow$ **React** (`possible`) |
| `astro` | **Astro** | `dom`: `[data-astro-cid-], astro-island`<br>`meta`: `generator` | data-astro-cid-\|astro-island<br>Astro(?:\s+v?([0-9.]+))? | 95<br>95 | - |
| `sveltekit` | **SvelteKit** | `dom`: `script[data-sveltekit-], div#svelte, link[rel='modulepreload'][href*='_app/immutable/']` | data-sveltekit\|__sveltekit\|_app/immutable\|div#svelte | 95 | $\rightarrow$ **Svelte** (`possible`)<br>$\rightarrow$ **Node.js** (`unknown`) |

---

### 3.6 クラウドホスティング・外部サービス・解析・セキュリティ (`hosting-cloud`, `analytics-tracking`, `security-service`)

| 技術ID | 技術名 | カテゴリ | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `vercel` | **Vercel** | `hosting-cloud` | `header`: `server`<br>`header`: `x-vercel-id`<br>`header`: `x-vercel-cache` | ^Vercel$<br>.*<br>.* | 95<br>95<br>90 |
| `netlify` | **Netlify** | `hosting-cloud` | `header`: `server`<br>`header`: `x-nf-request-id` | ^Netlify$<br>.* | 95<br>95 |
| `firebase-hosting` | **Firebase Hosting** | `hosting-cloud` | `header`: `x-firebase-hosting` | .* | 95 |
| `azure-app-service` | **Azure App Service** | `hosting-cloud` | `cookie`: `ARRAffinity`<br>`cookie`: `ARRAffinitySameSite` | ^ARRAffinity$<br>^ARRAffinitySameSite$ | 90<br>90 |
| `aws-alb` | **AWS Application Load Balancer** | `hosting-cloud` | `cookie`: `AWSALB`<br>`cookie`: `AWSALBCORS` | ^(?:AWSALB\|AWSELB)$<br>^(?:AWSALBCORS\|AWSELBCORS)$ | 90<br>90 |
| `aws-api-gateway` | **AWS API Gateway** | `hosting-cloud` | `header`: `x-amzn-requestid`<br>`header`: `x-amz-apigw-id` | .*<br>.* | 85<br>95 |
| `google-analytics` | **Google Analytics** | `analytics-tracking` | `script`: `src`<br>`cookie`: `_ga` | google-analytics\.com/(?:analytics\|ga)\.js\|googletagmanager\.com/gtag/js<br>^_ga$ | 90<br>85 |
| `google-tag-manager` | **Google Tag Manager** | `analytics-tracking` | `script`: `src`<br>`dom`: `iframe` | googletagmanager\.com/gtm\.js<br>googletagmanager\.com/ns\.html | 95<br>95 |
| `microsoft-clarity` | **Microsoft Clarity** | `analytics-tracking` | `script`: `src`<br>`cookie`: `_clck` | clarity\.ms/tag/<br>^_clck$ | 95<br>85 |
| `sentry` | **Sentry** | `security-service` | `script`: `src` | browser\.sentry-cdn\.com\|js\.sentry-cdn\.com | 95 |
| `recaptcha` | **reCAPTCHA** | `security-service` | `script`: `src`<br>`dom`: `.g-recaptcha` | google\.com/recaptcha/api\.js\|recaptcha/enterprise\.js<br>g-recaptcha | 95<br>90 |
| `hcaptcha` | **hCaptcha** | `security-service` | `script`: `src`<br>`dom`: `.h-captcha` | hcaptcha\.com/1/api\.js\|js\.hcaptcha\.com<br>h-captcha | 95<br>90 |

---

### 3.7 CDN / WAF (`cdn-waf`)

| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み |
| :--- | :--- | :--- | :--- | :--- |
| `cloudflare` | **Cloudflare** | `header`: `server`<br>`header`: `cf-ray`<br>`header`: `cf-cache-status`<br>`cookie`: `__cf_bm` | cloudflare<br>.*<br>.*<br>^__cf_bm$ | 95<br>95<br>90<br>85 |
| `cloudfront` | **Amazon CloudFront** | `header`: `x-amz-cf-id`<br>`header`: `via`<br>`header`: `x-cache` | .*<br>CloudFront<br>(?:Hit\|Miss\|Error) from cloudfront | 95<br>95<br>90 |
| `fastly` | **Fastly** | `header`: `x-served-by`<br>`header`: `fastly-debug-digest`<br>`header`: `x-fastly-request-id` | cache-[a-z0-9]+<br>.*<br>.* | 85<br>95<br>95 |
| `akamai` | **Akamai** | `header`: `x-akamai-transformed`<br>`header`: `server` | .*<br>AkamaiGHost | 95<br>95 |

---

## 4. Implication Engine（連動推論）連動マトリクス

Implication Engine は、親技術が直接検出された際に、依存関係にある子技術を自動的に補完する第2パスエンジンです。

```mermaid
graph LR
    Next["Next.js"] -->|"framework-dependency (confirmed)"| React["React"]
    Next -->|"possible-runtime (unknown)"| Node["Node.js"]
    
    Nuxt["Nuxt"] -->|"framework-dependency (confirmed)"| Vue["Vue.js"]
    Nuxt -->|"possible-runtime (unknown)"| Node
    
    SvelteKit["SvelteKit"] -->|"framework-dependency (confirmed)"| Svelte["Svelte"]
    SvelteKit -->|"possible-runtime (unknown)"| Node
    
    MUI["Material UI"] -->|"framework-dependency (confirmed)"| React
    
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
    ASPCore["ASP.NET Core"] -->|"runtime-dependency (unknown)"| DotNet[".NET"]
```

### 連動推論ルールと設計原則
1. **確信度上限クリップ**: 推論先の確信度は、推論元技術の確信度を超えないよう制御されます（$Score_{child} \le Score_{parent} \times Factor$）。
2. **循環防止**: `visitedEdges` によるトポロジカル探索を行い、`A -> B -> A` のような無限ループを完全に抑止します。
3. **静的配信への配慮**: Next.js や Nuxt からの Node.js 推論は、静的ホスティング（SSG）で配信されている可能性を考慮し、SSRの明確な証拠がない限り**「稼働未確認 (`unknown`)」**として記録します（※Astro は静的SSG配信が標準であるため、Node.js への自動連動推論は行いません）。

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
    Engine->>UI: 1行に集約して表示<br/>「Laravel / Spring Boot / Node.js (候補)」

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
| **WordPress** | `<meta name="generator">` またはコアアセット（`wp-embed.min.js?ver=6.4.2` 等）が存在 | テーマやCDN最適化でパラメータやgeneratorが除去されている場合 |
| **Bootstrap** | `window.bootstrap.Modal.VERSION` または CDN URL にバージョン記載 | Webpack等でバンドル・minifyされ、CSSクラスのみ使用されている場合 |
| **Angular** | DOMに `ng-version="16.2.0"` 属性が存在 | 本番ビルド時に属性が剥離されている場合 |

### 6.2 EOL / CVE 照合における安全設計とバックポート配慮
- **断定の回避**: バージョンが隠蔽されて特定できない場合は、「バージョン不明」として安全に扱い、**無関係なバージョンのCVEを誤報（False Positive）として出さない**安全機構（IMP-19）が働きます。
- **Linuxディストリビューション版（バックポート修正）への配慮**:
  `Server: Apache/2.4.41 (Ubuntu)` のように OS パッケージ版が使用されている場合、バージョン番号上は古く見えても、セキュリティパッチがバックポート（逆移植）されている可能性があります。そのため、診断レポート上では「バージョン表記上は該当。Linuxディストリビューション版（Ubuntu/RHEL等）の場合はバックポート修正済みの可能性あり（要確認）」と確度を分けてガイダンスします。
