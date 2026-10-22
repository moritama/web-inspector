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
      <a href="/insecure-cookie">/insecure-cookie (IMP-01)</a>
      <a href="/loose-csp">/loose-csp (IMP-02)</a>
      <a href="/legacy-lib">/legacy-lib (IMP-03)</a>
    </nav>
    ${content}
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost:3000'}`);
  const pathname = url.pathname;

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

  // --- 4. デフォルト (v1.1 テストページ) ---
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
});
