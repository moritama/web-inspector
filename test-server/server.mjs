/**
 * Web Technology & Security Inspector
 * テスト検証用ローカルHTTPサーバー (test-server/server.mjs) - Version 1.2.0
 * 
 * 以下のテストシグナル・エンドポイントをシミュレートします:
 * 1. / (デフォルト): v1.1 テストページ (Bootstrap 4.3.1, jQuery 3.6.0, WordPress 6.4.2)
 * 2. /insecure-cookie (IMP-01): 認証Cookieの属性欠落、CSRFトークンの意図的HttpOnly除外、設定・解析Cookie
 * 3. /loose-csp (IMP-02): 'unsafe-inline', 'unsafe-eval', '*', 'data:' 含む危険なCSP
 * 4. /legacy-lib (IMP-03): 古い jQuery 2.2.4 & WordPress 5.2 (既知脆弱性・EOL検知確認用)
 */

import http from 'node:http';

const PORT = 3000;

function createLayout(title, content) {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    nav { display: flex; gap: 1rem; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid #e2e8f0; }
    nav a { color: #2563eb; text-decoration: none; font-weight: 500; padding: 0.5rem 0.75rem; border-radius: 6px; }
    nav a:hover { background: #eff6ff; }
    h1 { font-size: 1.5rem; color: #0f172a; margin-top: 0; }
    .card { background: #f1f5f9; border-radius: 8px; padding: 1.25rem; margin-top: 1rem; }
    ul { margin: 0.5rem 0 0 1.25rem; }
    li { margin-bottom: 0.25rem; }
    code { background: #e2e8f0; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="container">
    <nav>
      <a href="/">デフォルト (v1.1)</a>
      <a href="/apache-positive">/apache-positive (Apache肯定)</a>
      <a href="/laravel-positive">/laravel-positive (Laravel肯定)</a>
      <a href="/angularjs-advisory">/angularjs-advisory (EOL/CVE)</a>
      <a href="/edge-cases">/edge-cases (エッジケース)</a>
      <a href="/rails-session">/rails-session (Rails単独)</a>
      <a href="/react18-app">/react18-app (React 18)</a>
      <a href="/vue3-app">/vue3-app (Vue 3)</a>
      <a href="/clear-cookies" style="color: #dc2626; font-weight: bold;">[Cookie全消去]</a>
    </nav>
    ${content}
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost:3000'}`);
  const pathname = url.pathname;

  // 目印つきの Set-Cookie を返すページ (Canary テスト用)
  if (pathname === '/cookie-canary') {
    res.setHeader('Set-Cookie', [
      'canary_session=CANARY_VALUE_7f3a91c2; Path=/; HttpOnly; SameSite=Lax',
      'canary_plain=CANARY_PLAIN_55e1b0; Path=/',
    ]);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>cookie canary</title><h1>cookie canary</h1>');
    return;
  }

  // ログイン直後のリダイレクトを模したページ(302 で Set-Cookie を返してから遷移)
  if (pathname === '/login-redirect') {
    res.statusCode = 302;
    res.setHeader('Set-Cookie', 'canary_login=CANARY_LOGIN_a91c33; Path=/; HttpOnly');
    res.setHeader('Location', '/after-login');
    res.end();
    return;
  }
  if (pathname === '/after-login') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>after login</title><h1>after login</h1>');
    return;
  }

  // 200 のログイン応答 (Set-Cookie を返す)
  if (pathname === '/login-200') {
    res.setHeader('Set-Cookie', 'canary_200=CANARY_LOGIN_200_ef881b; Path=/; HttpOnly');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>login 200</title><h1>login 200</h1>');
    return;
  }

  // Location ヘッダーにトークンを含む 302 リダイレクト
  if (pathname === '/token-redirect') {
    res.statusCode = 302;
    res.setHeader('Location', '/after-token?token=CANARY_TOKEN_99cc22');
    res.end();
    return;
  }
  if (pathname === '/after-token') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>after token</title><h1>after token</h1>');
    return;
  }

  // --- 1. /insecure-cookie (IMP-01: Cookie用途別判定テスト) ---
  if (pathname === '/insecure-cookie') {
    res.setHeader('Server', 'nginx/1.24.0');
    res.setHeader('Set-Cookie', [
      'PHPSESSID=insecure_session_token_999; Path=/; SameSite=Lax', // 認証系: Secure/HttpOnly欠落 -> High
      'auth_token=jwt_sample_without_httponly; Path=/; Secure; SameSite=Strict', // 認証系: HttpOnly欠落 -> High
      'XSRF-TOKEN=valid_csrf_token_value; Path=/; Secure; SameSite=Lax', // CSRF系: HttpOnlyなし (意図的) -> 許容/Info
      'theme_mode=dark; Path=/; SameSite=Lax', // UI設定: HttpOnly不要 -> Low/許容
      '_ga=GA1.2.12345678.1700000000; Path=/; SameSite=Lax', // トラッキング: HttpOnly不要 -> Low/許容
    ]);
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'IMP-01 Cookie用途別判定 テスト',
        `<h1>IMP-01: Cookie用途別判定テスト (/insecure-cookie)</h1>
        <p>このページでは以下のCookieを発行しています。Web InspectorでCookie診断を開き、重大度が用途別に適切に判定されるか確認してください。</p>
        <div class="card">
          <h3>発行されたCookieと期待される判定:</h3>
          <ul>
            <li><code>PHPSESSID</code>: 認証系 / Secure・HttpOnly欠落 $\\rightarrow$ <strong>High (重大)</strong></li>
            <li><code>auth_token</code>: 認証系 / HttpOnly欠落 $\\rightarrow$ <strong>High (重大)</strong></li>
            <li><code>XSRF-TOKEN</code>: CSRF系 / HttpOnly意図的欠落 $\\rightarrow$ <strong>Info (意図的・許容)</strong></li>
            <li><code>theme_mode</code>: UI設定系 $\\rightarrow$ <strong>不要な警告なし (ノイズ削減)</strong></li>
            <li><code>_ga</code>: アクセス解析系 $\\rightarrow$ <strong>不要な警告なし (ノイズ削減)</strong></li>
          </ul>
        </div>`
      )
    );
  }

  // --- 2. /loose-csp (IMP-02: CSP構文解析テスト) ---
  if (pathname === '/loose-csp') {
    res.setHeader('Server', 'Apache/2.4.52');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' * data:; style-src 'self' 'unsafe-inline';"
    );
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'IMP-02 CSP構文解析 テスト',
        `<h1>IMP-02: CSP構文解析テスト (/loose-csp)</h1>
        <p>このページでは危険なディレクティブが混在したCSPヘッダーを送信しています。</p>
        <div class="card">
          <h3>設定されているCSPヘッダー:</h3>
          <code>default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' * data:; style-src 'self' 'unsafe-inline';</code>
          <h3>期待される検出結果:</h3>
          <ul>
            <li><code>'unsafe-inline'</code> (script-src) $\\rightarrow$ <strong>High</strong> (XSSリスク)</li>
            <li><code>'unsafe-eval'</code> (script-src) $\\rightarrow$ <strong>Medium</strong> (eval動的コード生成)</li>
            <li><code>*</code> (script-src ワイルドカード) $\\rightarrow$ <strong>High</strong> (外部任意ドメイン許容)</li>
            <li><code>data:</code> (script-src) $\\rightarrow$ <strong>High</strong> (dataスキームインジェクション)</li>
            <li><code>object-src</code> 未指定 $\\rightarrow$ <strong>Medium</strong> (プラグイン未制限)</li>
            <li><code>frame-ancestors</code> 未指定 $\\rightarrow$ <strong>Medium</strong> (クリックジャッキングリスク)</li>
          </ul>
        </div>`
      )
    );
  }

  // --- 3. /legacy-lib (IMP-03: 古いライブラリ & EOL/CVE照合テスト) ---
  if (pathname === '/legacy-lib') {
    res.setHeader('Server', 'Apache/2.2.34 (Unix)'); // Apache 2.2系 (EOL)
    res.setHeader('X-Powered-By', 'PHP/7.4.33'); // PHP 7.4系 (EOL & CVE)
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);

    const legacyHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="generator" content="WordPress 5.2.4">
  <title>IMP-03 レガシーライブラリ & EOL照合テスト</title>
  <!-- jQuery 2.2.4 モック -->
  <script>
    window.jQuery = function() {};
    window.jQuery.fn = { jquery: "2.2.4" };
    window.$ = window.jQuery;
  </script>
</head>
<body style="font-family: sans-serif; padding: 2rem; background: #f8fafc;">
  <div style="max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px;">
    <nav style="margin-bottom: 1.5rem;"><a href="/" style="color: #2563eb;">← テストトップへ戻る</a></nav>
    <h1 style="color: #b91c1c;">IMP-03: レガシーライブラリ照合 (/legacy-lib)</h1>
    <p>このページはサポート終了（EOL）および既知脆弱性を持つ古い技術をシミュレートしています。</p>
    <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 1rem; border-radius: 6px;">
      <h3>検出対象と期待される診断:</h3>
      <ul>
        <li><strong>jQuery 2.2.4:</strong> EOL (2016-06) / CVE-2015-9251, CVE-2020-11022 (Potentially Affected)</li>
        <li><strong>WordPress 5.2.4:</strong> EOL (2024-01) / CVE-2022-21661, CVE-2023-32243 等</li>
        <li><strong>PHP 7.4.33:</strong> EOL (2022-11-28) / CVE-2022-31628</li>
        <li><strong>Apache 2.2.34:</strong> EOL (2017-12-31)</li>
      </ul>
    </div>
  </div>
</body>
</html>`;
    return res.end(legacyHtml);
  }

  // --- 4. /edge-cases (エッジケース・誤判定防止検証テスト) ---
  if (pathname === '/edge-cases') {
    // 1. Apache-Coyote (Tomcat) のレスポンスヘッダー (Apacheと誤認されないこと)
    res.setHeader('Server', 'Apache-Coyote/1.1');
    // 2. AWS Application Load Balancer Cookie
    res.setHeader('Set-Cookie', [
      'AWSALB=mock_alb_session_cookie_xyz789; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT',
      'AWSALBCORS=mock_alb_cors_cookie_xyz789; Path=/; SameSite=None; Secure',
    ]);
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);

    const edgeHtml = createLayout(
      'エッジケース・誤判定防止検証テスト',
      `<h1>エッジケース・誤判定防止検証テスト (/edge-cases)</h1>
      <p>このページでは、レビュアー指摘に基づき以下のエッジケース・特殊シグナルをシミュレートしています。実ブラウザでWeb Inspectorのポップアップを開き、判定結果を確認してください。</p>
      
      <div class="card">
        <h3>1. Vue 3 (scoped CSS 接頭辞属性)</h3>
        <p>以下の要素には <code>data-v-7ba5bd90</code> が付与されています（XPath属性走査で検出）：</p>
        <div data-v-7ba5bd90 style="padding: 0.5rem; background: #e0f2fe; border-radius: 4px; font-weight: bold;">
          Vue 3 Scoped Component Sample
        </div>
      </div>

      <div class="card">
        <h3>2. Google Tag Manager (noscript内iframe)</h3>
        <p>JavaScript有効環境でもnoscript内のtextContent走査によって検出されること：</p>
        <noscript>
          <iframe src="https://www.googletagmanager.com/ns.html?id=GTM-TEST9999" height="0" width="0" style="display:none;visibility:hidden"></iframe>
        </noscript>
        <code>&lt;noscript&gt;&lt;iframe src="https://www.googletagmanager.com/ns.html?id=GTM-TEST9999"&gt;&lt;/iframe&gt;&lt;/noscript&gt;</code>
      </div>

      <div class="card">
        <h3>3. AngularJS (ng-app属性)</h3>
        <p>固有属性セレクタによるAngularJSの検出（loading-spinner等の部分一致誤検知の解消）：</p>
        <div ng-app="sampleApp" ng-controller="SampleController" style="padding: 0.5rem; background: #fef3c7; border-radius: 4px; font-weight: bold;">
          AngularJS Application Component
        </div>
      </div>

      <div class="card">
        <h3>4. HTTPヘッダー・Cookie</h3>
        <ul>
          <li><code>Server: Apache-Coyote/1.1</code> $\\rightarrow$ <strong>Apacheと誤検知されないこと (未検出)</strong></li>
          <li><code>Set-Cookie: AWSALB=...</code> $\\rightarrow$ <strong>AWS Application Load Balancerが検出されること</strong></li>
        </ul>
      </div>`
    );
    return res.end(edgeHtml);
  }

  // --- 5. /rails-session (Rails Cookie単独でLaravelが誤検出されないことの検証) ---
  if (pathname === '/rails-session') {
    res.setHeader('Set-Cookie', [
      '_myapp_session=rails_mock_session_token_12345; Path=/; HttpOnly; SameSite=Lax',
    ]);
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);

    const railsHtml = createLayout(
      'Rails Session 単独テスト',
      `<h1>Rails Session 単独テスト (/rails-session)</h1>
      <p>このページでは、Railsの <code>Set-Cookie: _myapp_session=...</code> のみが発行されています。</p>
      <div class="card">
        <h3>期待される動作:</h3>
        <p><strong>Laravel は検出されないこと（未検出 / 0%）</strong></p>
        <p>先頭アンダースコア（<code>_myapp_session</code>）の除外ルールおよび単独低確信度Cookieの抑制により、Laravelと誤認されないことを確認してください。</p>
      </div>`
    );
    return res.end(railsHtml);
  }

  // --- 6. /react18-app (React 18 実機最小アプリ) ---
  if (pathname === '/react18-app') {
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);

    const reactHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>React 18 実機最小アプリ</title>
  <script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js"></script>
</head>
<body style="font-family: sans-serif; padding: 2rem;">
  <h1>React 18 実機最小アプリ (/react18-app)</h1>
  <div id="root"></div>
  <div style="margin-top: 1.5rem; padding: 1rem; background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px;">
    <strong>期待される動作:</strong>
    <ul>
      <li>React が検出され、バージョンが <code>18.2.0</code> と表示されること</li>
      <li>検出方式が <strong>直接検出 (direct)</strong> となること</li>
      <li>ランタイム状態が <strong>稼働確認済 (confirmed)</strong>（ルート要素の <code>__reactContainer$</code> 探査成功）となること</li>
    </ul>
  </div>
  <script>
    const e = React.createElement;
    function App() {
      return e('div', null, [
        e('h2', { key: '1' }, 'Hello from React 18 Root!'),
        e('p', { key: '2' }, 'ReactDOM.createRoot により #root 要素に __reactContainer$ が付与されています。')
      ]);
    }
    const root = ReactDOM.createRoot(document.getElementById('root'));
    root.render(e(App));
  </script>
</body>
</html>`;
    return res.end(reactHtml);
  }

  // --- 7. /vue3-app (Vue 3 実機最小アプリ) ---
  if (pathname === '/vue3-app') {
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);

    const vueHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Vue 3 実機最小アプリ</title>
  <script src="https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.prod.js"></script>
</head>
<body style="font-family: sans-serif; padding: 2rem;">
  <h1>Vue 3 実機最小アプリ (/vue3-app)</h1>
  <div id="app">
    <h2>{{ title }}</h2>
    <p>{{ description }}</p>
  </div>
  <div style="margin-top: 1.5rem; padding: 1rem; background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px;">
    <strong>期待される動作:</strong>
    <ul>
      <li>Vue.js が検出され、バージョンが <code>3.3.4</code> と表示されること</li>
      <li>検出方式が <strong>直接検出 (direct)</strong> となること</li>
      <li>ランタイム状態が <strong>稼働確認済 (confirmed)</strong>（ルート要素の <code>__vue_app__</code> 探査成功）となること</li>
    </ul>
  </div>
  <script>
    const { createApp } = Vue;
    createApp({
      data() {
        return {
          title: 'Hello from Vue 3 App!',
          description: 'Vue.createApp により #app 要素に __vue_app__ プロパティが付与されています。'
        };
      }
    }).mount('#app');
  </script>
</body>
</html>`;
    return res.end(vueHtml);
  }

  // --- 8. /clear-cookies (全テストCookieの消去) ---
  if (pathname === '/clear-cookies') {
    const expiredCookies = [
      'AWSALB=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      'AWSALBCORS=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; SameSite=None; Secure',
      'PHPSESSID=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      'auth_token=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      'XSRF-TOKEN=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      'theme_mode=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      '_ga=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      '_myapp_session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
      'laravel_session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0',
    ];
    res.setHeader('Set-Cookie', expiredCookies);
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'Cookie消去完了',
        `<h1>Cookie消去完了 (/clear-cookies)</h1>
        <p>テストサーバーが発行したすべてのCookie（AWSALB, PHPSESSID, _ga, _myapp_session等）に期限切れ（Max-Age=0）を設定しました。</p>
        <div class="card" style="background:#f0fdf4; border:1px solid #86efac;">
          <p>クリーンな状態で各エンドポイントの個別検証を実施できます。</p>
          <a href="/rails-session" style="color:#16a34a; font-weight:bold;">→ /rails-session (クリーン状態でRails単独確認)</a><br>
          <a href="/apache-positive" style="color:#2563eb; font-weight:bold;">→ /apache-positive (Apache肯定確認)</a><br>
          <a href="/laravel-positive" style="color:#2563eb; font-weight:bold;">→ /laravel-positive (Laravel肯定確認)</a>
        </div>`
      )
    );
  }

  // --- 9. /apache-positive (Apache肯定コントロール) ---
  if (pathname === '/apache-positive') {
    res.setHeader('Server', 'Apache/2.4.58 (Ubuntu)');
    res.setHeader('X-Powered-By', 'PHP/8.2.14');
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'Apache 肯定コントロールテスト',
        `<h1>Apache 肯定コントロールテスト (/apache-positive)</h1>
        <p>このページでは正規のApacheレスポンスヘッダーを送信しています。</p>
        <div class="card">
          <h3>レスポンスヘッダー:</h3>
          <ul>
            <li><code>Server: Apache/2.4.58 (Ubuntu)</code></li>
            <li><code>X-Powered-By: PHP/8.2.14</code></li>
          </ul>
          <h3>期待される検出結果:</h3>
          <ul>
            <li><strong>Apache</strong>: バージョン <code>2.4.58</code>、確信度 <strong>95% (High)</strong>、直接検出</li>
            <li><strong>PHP</strong>: バージョン <code>8.2.14</code>、確信度 <strong>95% (High)</strong>、直接検出</li>
          </ul>
        </div>`
      )
    );
  }

  // --- 10. /laravel-positive (Laravel肯定コントロール) ---
  if (pathname === '/laravel-positive') {
    res.setHeader('Set-Cookie', [
      'XSRF-TOKEN=sample_laravel_csrf_token_value; Path=/; SameSite=Lax',
      'laravel_session=sample_laravel_session_encrypted_value; Path=/; HttpOnly; SameSite=Lax',
    ]);
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'Laravel 肯定コントロールテスト',
        `<h1>Laravel 肯定コントロールテスト (/laravel-positive)</h1>
        <p>このページでは正規のLaravelセッションCookieおよびCSRFトークンを発行しています。</p>
        <div class="card">
          <h3>発行Cookie:</h3>
          <ul>
            <li><code>XSRF-TOKEN</code>: CSRFトークン</li>
            <li><code>laravel_session</code>: LaravelセッションCookie (HttpOnly)</li>
          </ul>
          <h3>期待される検出結果:</h3>
          <ul>
            <li><strong>Laravel</strong>: 検出方式 <strong>直接検出 (direct)</strong>、確信度 <strong>85% (High)</strong></li>
            <li><strong>PHP</strong>: 連動推論 (inferred) または関連技術として検出</li>
          </ul>
        </div>`
      )
    );
  }

  // --- 11. /angularjs-advisory (AngularJS EOL & 修正版なし脆弱性検証) ---
  if (pathname === '/angularjs-advisory') {
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'AngularJS EOL & 脆弱性検証',
        `<h1>AngularJS EOL & 脆弱性検証 (/angularjs-advisory)</h1>
        <p>このページでは AngularJS 1.8.2（最終系・修正版なしバージョン）をCDNから読み込み、固有属性 <code>ng-app</code> を設定しています。</p>
        <div ng-app="advisoryApp" style="padding:1rem; background:#fef3c7; border-radius:6px; margin: 1rem 0;">
          <strong>AngularJS 1.8.2 アプリケーション領域</strong>
        </div>
        <div class="card">
          <h3>期待される検出結果:</h3>
          <ul>
            <li><strong>AngularJS</strong>: バージョン <code>1.8.2</code>、稼働確認済 (confirmed)</li>
            <li><strong>サポート状況 (EOL)</strong>: <code>EOL (2022-01-01)</code></li>
            <li><strong>既知脆弱性 (CVE-2022-25869)</strong>: 「修正版なし」の明記（修正バージョンへの更新または緩和策の適用を検討してください）</li>
          </ul>
        </div>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>`
      )
    );
  }

  // --- 12. /negative-angular (loading-spinner等によるAngularJS誤検知防止検証) ---
  if (pathname === '/negative-angular') {
    res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    res.writeHead(200);
    return res.end(
      createLayout(
        'AngularJS 誤検知防止検証',
        `<h1>AngularJS 誤検知防止検証 (/negative-angular)</h1>
        <p>このページでは "loading-spinner" や "ng-loading" などの類似クラス名・属性を使用していますが、AngularJSの正規のディレクティブは存在しません。</p>
        <div class="loading-spinner ng-loading-indicator" data-test="spinner" style="padding:1rem; background:#f1f5f9; border-radius:6px; margin: 1rem 0;">
          一般的なスピナー要素（AngularJSではない）
        </div>
        <div class="card">
          <h3>期待される検出結果:</h3>
          <ul>
            <li><strong>AngularJS</strong>: 未検出（0件）であること</li>
          </ul>
        </div>`
      )
    );
  }

  // --- 8. デフォルト (v1.1 テストページ) ---
  res.setHeader('Server', 'Apache/2.4.58 (Unix)');
  res.setHeader('X-Powered-By', 'PHP/8.2.14');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");
  res.setHeader('Set-Cookie', [
    'PHPSESSID=mock_session_token_12345; Path=/; SameSite=Lax',
    'auth_token=sample_jwt_token; Path=/; Secure; HttpOnly; SameSite=Strict',
  ]);
  res.setHeader('Content-Type', 'text/html; charset=UTF-8');
  res.writeHead(200);

  const defaultContent = `
    <h1>Web Inspector テスト検証ハブ</h1>
    <p>Web Inspectorの各改善機能（IMP-01 〜 IMP-03）を検証するためのテストエンドポイントです。</p>
    <div class="card">
      <h3>テスト用エンドポイント一覧:</h3>
      <ul>
        <li><a href="/insecure-cookie"><strong>/insecure-cookie</strong></a>: Cookie用途別判定（認証、CSRF、解析、設定）の誤検知削減確認 (IMP-01)</li>
        <li><a href="/loose-csp"><strong>/loose-csp</strong></a>: CSPディレクティブ構文解析（unsafe-inline, unsafe-eval, ワイルドカード, object-src）確認 (IMP-02)</li>
        <li><a href="/legacy-lib"><strong>/legacy-lib</strong></a>: 古いjQuery 2.2.4, WordPress 5.2, PHP 7.4のオフラインEOL・CVE突合確認 (IMP-03)</li>
        <li><a href="/edge-cases"><strong>/edge-cases</strong></a>: レビュー指摘のエッジケース検証（Vue3 scoped CSS, GTM noscript, AngularJS, Apache-Coyote, AWSALB）</li>
      </ul>
    </div>
    <script>
      window.jQuery = function() {};
      window.jQuery.fn = {
        jquery: "3.6.0",
        modal: { Constructor: { VERSION: "4.3.1" } }
      };
      window.$ = window.jQuery;
    </script>
    <link rel="stylesheet" href="/lib/bootstrap-4.3.1/css/bootstrap.min.css">
  `;

  res.end(createLayout('Web Inspector テスト検証ハブ', defaultContent));
});

server.listen(PORT, () => {
  console.log(`[test-server] テストサーバーが起動しました: http://localhost:${PORT}`);
  console.log(`  - デフォルト: http://localhost:${PORT}/`);
  console.log(`  - Cookie用途別判定 (IMP-01): http://localhost:${PORT}/insecure-cookie`);
  console.log(`  - CSP構文解析 (IMP-02): http://localhost:${PORT}/loose-csp`);
  console.log(`  - レガシーライブラリ・EOL照合 (IMP-03): http://localhost:${PORT}/legacy-lib`);
  console.log(`  - エッジケース・誤判定防止検証: http://localhost:${PORT}/edge-cases`);
  console.log(`  - Rails Cookie誤検知防止検証: http://localhost:${PORT}/rails-session`);
  console.log(`  - React 18 実機検証: http://localhost:${PORT}/react18-app`);
  console.log(`  - Vue 3 実機検証: http://localhost:${PORT}/vue3-app`);
});
